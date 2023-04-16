use rand::rngs::OsRng;
use std::{marker::PhantomData, time::Instant};

use darkfi_sdk::{
    crypto::{
        constants::{
            sinsemilla::{OrchardCommitDomains, OrchardHashDomains},
            util::gen_const_array,
            NullifierK, OrchardFixedBases, OrchardFixedBasesFull, ValueCommitV,
            MERKLE_DEPTH_ORCHARD,
        },
        pallas,
        pasta_prelude::*,
    },
    pasta::group::GroupEncoding,
};
use halo2_gadgets::{
    ecc::{
        chip::{EccChip, EccConfig},
        FixedPoint, FixedPointBaseField, FixedPointShort, NonIdentityPoint, Point, ScalarFixed,
        ScalarFixedShort, ScalarVar,
    },
    utilities::lookup_range_check::LookupRangeCheckConfig,
};
use halo2_proofs::{
    circuit::{AssignedCell, Chip, Layouter, Region, SimpleFloorPlanner, Value},
    plonk::{
        Advice, Circuit, Column, ConstraintSystem, Error, Fixed, Instance as InstanceColumn,
        Selector,
    },
    poly::Rotation,
};

use darkfi::zk::{
    assign_free_advice,
    gadget::arithmetic::{ArithChip, ArithConfig, ArithInstruction},
    proof::{Proof, ProvingKey, VerifyingKey},
};

mod circuit;

trait NumericInstructions: Chip<pallas::Base> {
    /// Variable representing a number.
    type Num;

    fn load_private(
        &self,
        layouter: impl Layouter<pallas::Base>,
        a: Value<pallas::Base>,
    ) -> Result<Self::Num, Error>;

    fn load_constant(
        &self,
        layouter: impl Layouter<pallas::Base>,
        constant: pallas::Base,
    ) -> Result<Self::Num, Error>;

    fn mul(
        &self,
        layouter: impl Layouter<pallas::Base>,
        a: Self::Num,
        b: Self::Num,
    ) -> Result<Self::Num, Error>;

    fn expose_public(
        &self,
        layouter: impl Layouter<pallas::Base>,
        num: Self::Num,
        row: usize,
    ) -> Result<(), Error>;
}

/// The chip that will implement our instructions! Chips store their own
/// config, as well as type markers if necessary.
struct FieldChip {
    config: FieldConfig,
}

/// Chip state is stored in a config struct. This is generated by the chip
/// during configuration, and then stored inside the chip.
#[derive(Clone, Debug)]
struct FieldConfig {
    /// For this chip, we will use two advice columns to implement our instructions.
    /// These are also the columns through which we communicate with other parts of
    /// the circuit.
    advice: [Column<Advice>; 2],

    /// This is the public input (instance) column.
    instance: Column<InstanceColumn>,

    // We need a selector to enable the multiplication gate, so that we aren't placing
    // any constraints on cells where `NumericInstructions::mul` is not being used.
    // This is important when building larger circuits, where columns are used by
    // multiple sets of instructions.
    s_mul: Selector,
}

impl FieldChip {
    fn construct(config: <Self as Chip<pallas::Base>>::Config) -> Self {
        Self { config }
    }

    fn configure(
        meta: &mut ConstraintSystem<pallas::Base>,
        advice: [Column<Advice>; 2],
        instance: Column<InstanceColumn>,
        constant: Column<Fixed>,
    ) -> <Self as Chip<pallas::Base>>::Config {
        meta.enable_equality(instance);
        meta.enable_constant(constant);
        for column in &advice {
            meta.enable_equality(*column);
        }
        let s_mul = meta.selector();

        // Define our multiplication gate!
        meta.create_gate("mul", |meta| {
            // To implement multiplication, we need three advice cells and a selector
            // cell. We arrange them like so:
            //
            // | a0  | a1  | s_mul |
            // |-----|-----|-------|
            // | lhs | rhs | s_mul |
            // | out |     |       |
            //
            // Gates may refer to any relative offsets we want, but each distinct
            // offset adds a cost to the proof. The most common offsets are 0 (the
            // current row), 1 (the next row), and -1 (the previous row), for which
            // `Rotation` has specific constructors.
            let lhs = meta.query_advice(advice[0], Rotation::cur());
            let rhs = meta.query_advice(advice[1], Rotation::cur());
            let out = meta.query_advice(advice[0], Rotation::next());
            let s_mul = meta.query_selector(s_mul);

            // Finally, we return the polynomial expressions that constrain this gate.
            // For our multiplication gate, we only need a single polynomial constraint.
            //
            // The polynomial expressions returned from `create_gate` will be
            // constrained by the proving system to equal zero. Our expression
            // has the following properties:
            // - When s_mul = 0, any value is allowed in lhs, rhs, and out.
            // - When s_mul != 0, this constrains lhs * rhs = out.
            vec![s_mul * (lhs * rhs - out)]
        });

        FieldConfig { advice, instance, s_mul }
    }
}

impl Chip<pallas::Base> for FieldChip {
    type Config = FieldConfig;
    type Loaded = ();

    fn config(&self) -> &Self::Config {
        &self.config
    }

    fn loaded(&self) -> &Self::Loaded {
        &()
    }
}

/// A variable representing a number.
#[derive(Clone)]
struct Number(AssignedCell<pallas::Base, pallas::Base>);

impl NumericInstructions for FieldChip {
    type Num = Number;

    fn load_private(
        &self,
        mut layouter: impl Layouter<pallas::Base>,
        value: Value<pallas::Base>,
    ) -> Result<Self::Num, Error> {
        let config = self.config();

        layouter.assign_region(
            || "load private",
            |mut region| {
                region.assign_advice(|| "private input", config.advice[0], 0, || value).map(Number)
            },
        )
    }

    fn load_constant(
        &self,
        mut layouter: impl Layouter<pallas::Base>,
        constant: pallas::Base,
    ) -> Result<Self::Num, Error> {
        let config = self.config();

        layouter.assign_region(
            || "load constant",
            |mut region| {
                region
                    .assign_advice_from_constant(|| "constant value", config.advice[0], 0, constant)
                    .map(Number)
            },
        )
    }

    fn mul(
        &self,
        mut layouter: impl Layouter<pallas::Base>,
        a: Self::Num,
        b: Self::Num,
    ) -> Result<Self::Num, Error> {
        let config = self.config();

        layouter.assign_region(
            || "mul",
            |mut region: Region<'_, pallas::Base>| {
                // We only want to use a single multiplication gate in this region,
                // so we enable it at region offset 0; this means it will constrain
                // cells at offsets 0 and 1.
                config.s_mul.enable(&mut region, 0)?;

                // The inputs we've been given could be located anywhere in the circuit,
                // but we can only rely on relative offsets inside this region. So we
                // assign new cells inside the region and constrain them to have the
                // same values as the inputs.
                a.0.copy_advice(|| "lhs", &mut region, config.advice[0], 0)?;
                b.0.copy_advice(|| "rhs", &mut region, config.advice[1], 0)?;

                // Now we can assign the multiplication result, which is to be assigned
                // into the output position.
                let value = a.0.value().copied() * b.0.value();

                // Finally, we do the assignment to the output, returning a
                // variable to be used in another part of the circuit.
                region.assign_advice(|| "lhs * rhs", config.advice[0], 1, || value).map(Number)
            },
        )
    }

    fn expose_public(
        &self,
        mut layouter: impl Layouter<pallas::Base>,
        num: Self::Num,
        row: usize,
    ) -> Result<(), Error> {
        let config = self.config();

        layouter.constrain_instance(num.0.cell(), config.instance, row)
    }
}

#[derive(Clone)]
pub struct MainConfig {
    primary: Column<InstanceColumn>,
    advices: [Column<Advice>; 10],
    ecc_config: EccConfig<OrchardFixedBases>,
    arith_config: ArithConfig,
}

impl MainConfig {
    fn ecc_chip(&self) -> EccChip<OrchardFixedBases> {
        EccChip::construct(self.ecc_config.clone())
    }

    fn arithmetic_chip(&self) -> ArithChip {
        ArithChip::construct(self.arith_config.clone())
    }
}

#[derive(Default)]
struct MyCircuit {
    g1: Value<pallas::Point>,
    //g2: Value<pallas::Point>,
    //g3: Value<pallas::Point>,
    //g4: Value<pallas::Point>,
    s1: Value<pallas::Base>,
    //s2: Value<pallas::Scalar>,
    //s3: Value<pallas::Scalar>,
    //s4: Value<pallas::Scalar>,
}

impl Circuit<pallas::Base> for MyCircuit {
    // Since we are using a single chip for everything, we can just reuse its config.
    type Config = MainConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<pallas::Base>) -> Self::Config {
        //  Advice columns used in the circuit
        let advices = [
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
        ];

        // Fixed columns for the Sinsemilla generator lookup table
        let table_idx = meta.lookup_table_column();
        let lookup = (table_idx, meta.lookup_table_column(), meta.lookup_table_column());

        // Instance column used for public inputs
        let primary = meta.instance_column();
        meta.enable_equality(primary);

        // Permutation over all advice columns
        for advice in advices.iter() {
            meta.enable_equality(*advice);
        }

        // Poseidon requires four advice columns, while ECC incomplete addition
        // requires six. We can reduce the proof size by sharing fixed columns
        // between the ECC and Poseidon chips.
        // TODO: For multiple invocations perhaps they could/should be configured
        // in parallel rather than sharing?
        let lagrange_coeffs = [
            meta.fixed_column(),
            meta.fixed_column(),
            meta.fixed_column(),
            meta.fixed_column(),
            meta.fixed_column(),
            meta.fixed_column(),
            meta.fixed_column(),
            meta.fixed_column(),
        ];
        //let rc_a = lagrange_coeffs[2..5].try_into().unwrap();
        //let rc_b = lagrange_coeffs[5..8].try_into().unwrap();

        // Also use the first Lagrange coefficient column for loading global constants.
        meta.enable_constant(lagrange_coeffs[0]);

        // Use one of the right-most advice columns for all of our range checks.
        let range_check = LookupRangeCheckConfig::configure(meta, advices[9], table_idx);

        // Configuration for curve point operations.
        // This uses 10 advice columns and spans the whole circuit.
        let ecc_config =
            EccChip::<OrchardFixedBases>::configure(meta, advices, lagrange_coeffs, range_check);

        // Configuration for the Poseidon hash
        //let poseidon_config = PoseidonChip::configure::<poseidon::P128Pow5T3>(
        //    meta,
        //    advices[6..9].try_into().unwrap(),
        //    advices[5],
        //    rc_a,
        //    rc_b,
        //);

        // Configuration for the Arithmetic chip
        let arith_config = ArithChip::configure(meta, advices[7], advices[8], advices[6]);

        // Configuration for a Sinsemilla hash instantiation and a
        // Merkle hash instantiation using this Sinsemilla instance.
        // Since the Sinsemilla config uses only 5 advice columns,
        // we can fit two instances side-by-side.
        //let (sinsemilla_cfg1, merkle_cfg1) = {
        //    let sinsemilla_cfg1 = SinsemillaChip::configure(
        //        meta,
        //        advices[..5].try_into().unwrap(),
        //        advices[6],
        //        lagrange_coeffs[0],
        //        lookup,
        //        range_check,
        //    );
        //    let merkle_cfg1 = MerkleChip::configure(meta, sinsemilla_cfg1.clone());
        //    (sinsemilla_cfg1, merkle_cfg1)
        //};

        //let (_sinsemilla_cfg2, merkle_cfg2) = {
        //    let sinsemilla_cfg2 = SinsemillaChip::configure(
        //        meta,
        //        advices[5..].try_into().unwrap(),
        //        advices[7],
        //        lagrange_coeffs[1],
        //        lookup,
        //        range_check,
        //    );
        //    let merkle_cfg2 = MerkleChip::configure(meta, sinsemilla_cfg2.clone());
        //    (sinsemilla_cfg2, merkle_cfg2)
        //};

        // K-table for 64 bit range check lookups
        let k_values_table_64 = meta.lookup_table_column();
        //let native_64_range_check_config =
        //    NativeRangeCheckChip::<3, 64, 22>::configure(meta, advices[8], k_values_table_64);

        // K-table for 253 bit range check lookups
        let k_values_table_253 = meta.lookup_table_column();
        //let native_253_range_check_config =
        //    NativeRangeCheckChip::<3, 253, 85>::configure(meta, advices[8], k_values_table_253);

        // TODO: FIXME: Configure these better, this is just a stop-gap
        let z1 = meta.advice_column();
        let z2 = meta.advice_column();
        //
        //let lessthan_config = LessThanChip::<3, 253, 85>::configure(
        //    meta,
        //    advices[6],
        //    advices[7],
        //    advices[8],
        //    z1,
        //    z2,
        //    k_values_table_253,
        //);

        // Configuration for boolean checks, it uses the small_range_check
        // chip with a range of 2, which enforces one bit, i.e. 0 or 1.
        //let boolcheck_config = SmallRangeCheckChip::configure(meta, advices[9], 2);

        MainConfig { primary, advices, ecc_config, arith_config }
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<pallas::Base>,
    ) -> Result<(), Error> {
        let g1 = NonIdentityPoint::new(
            config.ecc_chip(),
            layouter.namespace(|| "Witness EcNiPoint"),
            self.g1.as_ref().map(|cm| cm.to_affine()),
        )?;

        let s1 = assign_free_advice(layouter.namespace(|| "load a"), config.advices[0], self.s1)?;
        let s1: AssignedCell<pallas::Base, pallas::Base> = s1.into();
        let s1 = ScalarVar::from_base(
            config.ecc_chip(),
            layouter.namespace(|| "EcMul: ScalarFixed::new()"),
            &s1,
        )?;
        let (r, _) = g1.mul(layouter.namespace(|| "EcMul()"), s1)?;

        let mut public_inputs_offset = 0;

        let point: Point<pallas::Affine, EccChip<OrchardFixedBases>> = r.into();
        let r_x = point.inner().x();
        let r_y = point.inner().y();

        let var: AssignedCell<pallas::Base, pallas::Base> = r_x.into();
        layouter.constrain_instance(var.cell(), config.primary, public_inputs_offset)?;
        public_inputs_offset += 1;

        let var: AssignedCell<pallas::Base, pallas::Base> = r_y.into();
        layouter.constrain_instance(var.cell(), config.primary, public_inputs_offset)?;
        public_inputs_offset += 1;

        Ok(())
    }
}

fn main() -> std::result::Result<(), Box<dyn std::error::Error>> {
    let k = 8;

    //let g1 = pallas::Point::random(&mut OsRng);
    //println!("{:?}", g1);
    //let g1_bytes = g1.to_bytes();
    //println!("{}", hex::encode(&g1_bytes));

    // G1_x = 2fea7c1d8106d6d407a57bebec987e875ed9073ebf215e52f5b42c0c604c1801
    // G1_y = 0dcc7041075d6496102295722cd12f2f0c1e9d49eaa00f10c4bc02155598353b
    // G2_x = dfae4ed869484b2b9783c445888db03bac24f96f0260982b90f5b53477994e3e
    // G2_y = fa1b4182ef04514624a1e32846d48bfd229ef78975106e8e0614b8061dfe3d1d
    // G3_x = 702ddc6514ae63da6e13bcfa439f03b363018a152e16e665126623205ac4d31c
    // G3_y = 81cb38e121b6c375150aa2c1b4c92185a87781194a133535cbefb699e3475103
    // G4_x = 026b681bf7a0102e78bf3b34af50b5031ef1dd1f152f3df17af8e6eaae69cb3a
    // G4_y = c97b4f5ed89f4147eb3410892af8a1ecd21b96f59d43e5e4252872742acbbf24

    // s1 = f4537d29a235d6b4bf95ef436aa15fd641419c2da9e9600520be99a14c43ac2c
    // s2 = 6d2738d1e1f8bbb1bd154cd8102cca5c0224f8902803da1f7c4563b47103471c
    // s3 = ebbaf604f85b3e725e71a5d785e177c9f3ccd4c07394a0d59318cf1504c72a06
    // s4 = 5176cd889dd29f19cef07c5d2db9a2d67c568034ae737ff1f95456252d2e2301

    // Qx = 6b35d97bcef7928a15aed8e5d9b8ecbcb2a5ca190de7b9957971f6da6ad92c03
    // Qy = e485978ca7d9f798fe1b7afac7f74a98326cccc528f1010091948497ae5e7422

    // Halo2 points are the x coordinated in little endian order
    let g1x_bytes =
        hex::decode("2fea7c1d8106d6d407a57bebec987e875ed9073ebf215e52f5b42c0c604c1801")?;
    let g1x_bytes = g1x_bytes[..].try_into()?;
    let g1x = pallas::Base::from_repr(g1x_bytes).unwrap();
    let g1y_bytes =
        hex::decode("0dcc7041075d6496102295722cd12f2f0c1e9d49eaa00f10c4bc02155598353b")?;
    let g1y_bytes = g1y_bytes[..].try_into()?;
    let g1y = pallas::Base::from_repr(g1y_bytes).unwrap();
    let g1: pallas::Point = pallas::Affine::from_xy(g1x, g1y).unwrap().into();

    //let g2x_bytes = hex::decode("dfae4ed869484b2b9783c445888db03bac24f96f0260982b90f5b53477994e3e")?;
    //let g2x_bytes = g2x_bytes[..].try_into()?;
    //let g2x = pallas::Base::from_repr(g2x_bytes).unwrap();
    //let g2y_bytes = hex::decode("fa1b4182ef04514624a1e32846d48bfd229ef78975106e8e0614b8061dfe3d1d")?;
    //let g2y_bytes = g2y_bytes[..].try_into()?;
    //let g2y = pallas::Base::from_repr(g2y_bytes).unwrap();
    //let g2: pallas::Point = pallas::Affine::from_xy(g2x, g2y).unwrap().into();

    //let g3x_bytes = hex::decode("702ddc6514ae63da6e13bcfa439f03b363018a152e16e665126623205ac4d31c")?;
    //let g3x_bytes = g3x_bytes[..].try_into()?;
    //let g3x = pallas::Base::from_repr(g3x_bytes).unwrap();
    //let g3y_bytes = hex::decode("81cb38e121b6c375150aa2c1b4c92185a87781194a133535cbefb699e3475103")?;
    //let g3y_bytes = g3y_bytes[..].try_into()?;
    //let g3y = pallas::Base::from_repr(g3y_bytes).unwrap();
    //let g3: pallas::Point = pallas::Affine::from_xy(g3x, g3y).unwrap().into();

    //let g4x_bytes = hex::decode("026b681bf7a0102e78bf3b34af50b5031ef1dd1f152f3df17af8e6eaae69cb3a")?;
    //let g4x_bytes = g4x_bytes[..].try_into()?;
    //let g4x = pallas::Base::from_repr(g4x_bytes).unwrap();
    //let g4y_bytes = hex::decode("c97b4f5ed89f4147eb3410892af8a1ecd21b96f59d43e5e4252872742acbbf24")?;
    //let g4y_bytes = g4y_bytes[..].try_into()?;
    //let g4y = pallas::Base::from_repr(g4y_bytes).unwrap();
    //let g4: pallas::Point = pallas::Affine::from_xy(g4x, g4y).unwrap().into();

    //let s1_bytes = hex::decode("f4537d29a235d6b4bf95ef436aa15fd641419c2da9e9600520be99a14c43ac2c")?;
    //let s1_bytes = s1_bytes[..].try_into()?;
    //let s1 = pallas::Scalar::from_repr(s1_bytes).unwrap();

    //let s2_bytes = hex::decode("6d2738d1e1f8bbb1bd154cd8102cca5c0224f8902803da1f7c4563b47103471c")?;
    //let s2_bytes = s2_bytes[..].try_into()?;
    //let s2 = pallas::Scalar::from_repr(s2_bytes).unwrap();

    //let s3_bytes = hex::decode("ebbaf604f85b3e725e71a5d785e177c9f3ccd4c07394a0d59318cf1504c72a06")?;
    //let s3_bytes = s3_bytes[..].try_into()?;
    //let s3 = pallas::Scalar::from_repr(s3_bytes).unwrap();

    //let s4_bytes = hex::decode("5176cd889dd29f19cef07c5d2db9a2d67c568034ae737ff1f95456252d2e2301")?;
    //let s4_bytes = s4_bytes[..].try_into()?;
    //let s4 = pallas::Scalar::from_repr(s4_bytes).unwrap();

    //let qx_bytes = hex::decode("6b35d97bcef7928a15aed8e5d9b8ecbcb2a5ca190de7b9957971f6da6ad92c03")?;
    //let qx_bytes = qx_bytes[..].try_into()?;
    //let qx = pallas::Base::from_repr(qx_bytes).unwrap();
    //let qy_bytes = hex::decode("e485978ca7d9f798fe1b7afac7f74a98326cccc528f1010091948497ae5e7422")?;
    //let qy_bytes = qy_bytes[..].try_into()?;
    //let qy = pallas::Base::from_repr(qy_bytes).unwrap();
    //let q: pallas::Point = pallas::Affine::from_xy(qx, qy).unwrap().into();

    //let x = pallas::Scalar::from(2);
    //println!("{:?}", x);
    //println!("{:?}", x.to_repr());

    //let qq = g1*s1 + g2*s2 + g3*s3 + g4*s4;
    //println!("{:?}", qq.to_affine());
    //assert_eq!(q.to_affine(), qq.to_affine());

    let r = g1 * pallas::Scalar::from(2);

    let s1 = pallas::Base::from(2);

    let circuit = MyCircuit {
        g1: Value::known(g1),
        //g2: Value::known(g2),
        //g3: Value::known(g3),
        //g4: Value::known(g4),
        s1: Value::known(s1),
        //s2: Value::known(s2),
        //s3: Value::known(s3),
        //s4: Value::known(s4),
    };

    let r_coords = r.to_affine().coordinates().unwrap();
    let r_x = *r_coords.x();
    let r_y = *r_coords.y();

    let public = vec![r_x, r_y];

    let start = Instant::now();
    let pk = darkfi::zk::ProvingKey::build(k, &MyCircuit::default());
    let vk = darkfi::zk::VerifyingKey::build(k, &MyCircuit::default());
    println!("Setup: [{:?}]", start.elapsed());

    let start = Instant::now();
    let proof = Proof::create(&pk, &[circuit], &public, &mut OsRng)?;
    println!("Prove: [{:?}]", start.elapsed());

    let start = Instant::now();
    assert!(proof.verify(&vk, &public).is_ok());
    println!("Verify: [{:?}]", start.elapsed());
    Ok(())
}