/* This file is part of DarkFi (https://dark.fi)
 *
 * Copyright (C) 2020-2023 Dyne.org foundation
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

//! This API is crufty. Please rework it into something nice to read and nice to use.

use darkfi::{
    zk::{Proof, ProvingKey},
    zkas::ZkBinary,
    ClientFailed, Result,
};
use darkfi_sdk::{
    crypto::{
        note::AeadEncryptedNote, pasta_prelude::*, Keypair, MerkleTree, SecretKey, DARK_TOKEN_ID,
    },
    incrementalmerkletree::Tree,
    pasta::pallas,
};
use log::{debug, error, info};
use rand::rngs::OsRng;

use super::{
    transfer_v1::{
        compute_remainder_blind, create_transfer_burn_proof, create_transfer_mint_proof,
        TransactionBuilderInputInfo, TransactionBuilderOutputInfo,
    },
    MoneyNote, OwnCoin,
};
use crate::model::{Input, MoneyFeeParamsV1, Output};

pub struct FeeCallDebris {
    pub params: MoneyFeeParamsV1,
    pub proofs: Vec<Proof>,
    pub signature_secrets: Vec<SecretKey>,
    pub spent_coins: Vec<OwnCoin>,
}

/// Struct holding necessary information to build a `Money::FeeV1` contract call.
pub struct FeeCallBuilder {
    /// Caller's keypair
    pub keypair: Keypair,
    /// Fee amount that should be paid
    pub value: u64,
    /// Spend hook for the change output
    pub change_spend_hook: pallas::Base,
    /// User data for the change output
    pub change_user_data: pallas::Base,
    /// User data blind for the change output
    pub change_user_data_blind: pallas::Base,
    /// Set of `OwnCoin` we're given to use in this builder
    pub coins: Vec<OwnCoin>,
    /// Merkle tree of coins used to create inclusion proofs
    pub tree: MerkleTree,
    /// `Mint_V1` zkas circuit ZkBinary
    pub mint_zkbin: ZkBinary,
    /// Proving key for the `Mint_V1` zk circuit
    pub mint_pk: ProvingKey,
    /// `Burn_V1` zkas circuit ZkBinary
    pub burn_zkbin: ZkBinary,
    /// Proving key for the `Burn_V1` zk circuit
    pub burn_pk: ProvingKey,
}

impl FeeCallBuilder {
    pub fn build(&self, dummy: bool) -> Result<FeeCallDebris> {
        debug!("Building Money::FeeV1 contract call");
        assert!(self.value != 0);

        // Ensure the coins given to us are the native token
        for coin in self.coins.iter() {
            assert_eq!(coin.note.token_id.inner(), DARK_TOKEN_ID.inner());
        }

        let mut inputs = vec![];
        let mut outputs = vec![];
        let mut spent_coins = vec![];
        let mut signature_secrets = vec![];
        let mut proofs = vec![];

        debug!("Building anonymous inputs");
        let mut inputs_value = 0;

        // Clone the Merkle tree as mutable for potential changes in the
        // scope of this function
        let mut scoped_tree = self.tree.clone();
        let root = scoped_tree.root(0).unwrap();

        for coin in self.coins.iter() {
            if inputs_value >= self.value {
                break
            }

            let (leaf_position, merkle_path) = if dummy {
                // In the case of dummy inputs, we will just provide a Merkle path to the
                // latest leaf appended into the tree.
                scoped_tree.witness();
                let leaf_position = scoped_tree.current_position().unwrap();
                let merkle_path = scoped_tree.authentication_path(leaf_position, &root).unwrap();
                scoped_tree.remove_witness(leaf_position);
                (leaf_position, merkle_path)
            } else {
                // Otherwise we provide an actual respective path.
                let leaf_position = coin.leaf_position;
                let merkle_path = scoped_tree.authentication_path(leaf_position, &root).unwrap();
                (leaf_position, merkle_path)
            };

            inputs_value += coin.note.value;

            let input = TransactionBuilderInputInfo {
                leaf_position,
                merkle_path,
                secret: coin.secret,
                note: coin.note.clone(),
            };

            inputs.push(input);
            spent_coins.push(coin.clone());
        }

        if inputs_value < self.value {
            error!("Not enough value to build tx inputs");
            return Err(ClientFailed::NotEnoughValue(inputs_value).into())
        }

        if inputs_value > self.value {
            let return_value = inputs_value - self.value;
            outputs.push(TransactionBuilderOutputInfo {
                value: return_value,
                token_id: *DARK_TOKEN_ID,
                public_key: self.keypair.public,
            });
        }

        assert!(!inputs.is_empty());
        debug!("Finished building inputs");

        // Create a public blind for the fee the token
        let token_blind = pallas::Scalar::random(&mut OsRng);

        let mut params = MoneyFeeParamsV1 {
            inputs: vec![],
            outputs: vec![],
            fee_value: self.value,
            fee_value_blind: pallas::Scalar::zero(),
            token_blind,
        };

        let mut input_blinds = vec![];
        let mut output_blinds = vec![];

        for (i, input) in inputs.iter().enumerate() {
            let value_blind = pallas::Scalar::random(&mut OsRng);
            input_blinds.push(value_blind);

            let signature_secret = SecretKey::random(&mut OsRng);
            signature_secrets.push(signature_secret);

            info!("Creating fee burn proof for input {}", i);
            let (proof, public_inputs) = create_transfer_burn_proof(
                &self.burn_zkbin,
                &self.burn_pk,
                input,
                value_blind,
                token_blind,
                self.change_user_data_blind, // FIXME: We assume this, but it's just 1 usecase
                signature_secret,
            )?;

            params.inputs.push(Input {
                value_commit: public_inputs.value_commit,
                token_commit: public_inputs.token_commit,
                nullifier: public_inputs.nullifier,
                merkle_root: public_inputs.merkle_root,
                spend_hook: public_inputs.spend_hook, // FIXME: Do we need spend hook here?
                user_data_enc: public_inputs.user_data_enc,
                signature_public: public_inputs.signature_public,
            });

            proofs.push(proof);
        }

        for (i, output) in outputs.iter().enumerate() {
            let value_blind = pallas::Scalar::random(&mut OsRng);
            output_blinds.push(value_blind);

            let serial = pallas::Base::random(&mut OsRng);
            let coin_blind = pallas::Base::random(&mut OsRng);

            info!("Creating fee mint proof for output {}", i);
            let (proof, public_inputs) = create_transfer_mint_proof(
                &self.mint_zkbin,
                &self.mint_pk,
                output,
                value_blind,
                token_blind,
                serial,
                self.change_spend_hook,
                self.change_user_data,
                coin_blind,
            )?;

            proofs.push(proof);

            // Encrypted note
            let note = MoneyNote {
                serial,
                value: output.value,
                token_id: output.token_id,
                spend_hook: self.change_spend_hook,
                user_data: self.change_user_data,
                coin_blind,
                value_blind,
                token_blind,
                memo: vec![],
            };

            let encrypted_note = AeadEncryptedNote::encrypt(&note, &output.public_key, &mut OsRng)?;

            params.outputs.push(Output {
                value_commit: public_inputs.value_commit,
                token_commit: public_inputs.token_commit,
                coin: public_inputs.coin,
                note: encrypted_note,
            });
        }

        // With the current info we have, now we can also calculate the remainder
        // blind for the fee:
        params.fee_value_blind = compute_remainder_blind(&[], &input_blinds, &output_blinds);

        // Now we should have all the params, zk proofs, and signature secrets.
        // We return it and let the caller deal with it.
        let debris = FeeCallDebris { params, proofs, signature_secrets, spent_coins };
        Ok(debris)
    }
}
