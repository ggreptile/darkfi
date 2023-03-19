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

use darkfi_sdk::{
    crypto::{
        pasta_prelude::*, pedersen_commitment_base, pedersen_commitment_u64, Coin, ContractId,
        MerkleNode, PublicKey, DARK_TOKEN_ID,
    },
    db::{db_contains_key, db_get, db_lookup, db_set},
    error::{ContractError, ContractResult},
    merkle_add, msg,
    pasta::pallas,
    ContractCall,
};
use darkfi_serial::{deserialize, serialize, Encodable, WriteExt};

use crate::{
    error::MoneyError,
    model::{MoneyFeeParamsV1, MoneyFeeUpdateV1},
    MoneyFunction, MONEY_CONTRACT_COINS_TREE, MONEY_CONTRACT_COIN_MERKLE_TREE,
    MONEY_CONTRACT_COIN_ROOTS_TREE, MONEY_CONTRACT_FAUCET_PUBKEYS, MONEY_CONTRACT_INFO_TREE,
    MONEY_CONTRACT_NULLIFIERS_TREE, MONEY_CONTRACT_PAID_FEES, MONEY_CONTRACT_ZKAS_BURN_NS_V1,
    MONEY_CONTRACT_ZKAS_MINT_NS_V1,
};

/// `get_metadata` function for `Money::FeeV1`
pub(crate) fn money_fee_get_metadata_v1(
    _cid: ContractId,
    call_idx: u32,
    calls: Vec<ContractCall>,
) -> Result<Vec<u8>, ContractError> {
    // The fee should always be the first call in a transaction
    if call_idx != 0 {
        msg!("[FeeV1] Error: call idx is not 0");
        return Err(MoneyError::CallIdxNonZero.into())
    }

    let self_ = &calls[call_idx as usize];
    let params: MoneyFeeParamsV1 = deserialize(&self_.data[1..])?;

    // Public inputs for the ZK proofs we have to verify
    let mut zk_public_inputs: Vec<(String, Vec<pallas::Base>)> = vec![];
    // Public keys for the transaction signatures we have to verify
    let mut signature_pubkeys: Vec<PublicKey> = vec![];

    for input in &params.inputs {
        let value_coords = input.value_commit.to_affine().coordinates().unwrap();
        let token_coords = input.value_commit.to_affine().coordinates().unwrap();
        let (sig_x, sig_y) = input.signature_public.xy();

        zk_public_inputs.push((
            MONEY_CONTRACT_ZKAS_BURN_NS_V1.to_string(),
            vec![
                input.nullifier.inner(),
                *value_coords.x(),
                *value_coords.y(),
                *token_coords.x(),
                input.merkle_root.inner(),
                input.user_data_enc,
                sig_x,
                sig_y,
            ],
        ));

        signature_pubkeys.push(input.signature_public);
    }

    for output in &params.outputs {
        let value_coords = output.value_commit.to_affine().coordinates().unwrap();
        let token_coords = output.token_commit.to_affine().coordinates().unwrap();

        zk_public_inputs.push((
            MONEY_CONTRACT_ZKAS_MINT_NS_V1.to_string(),
            vec![
                output.coin.inner(),
                *value_coords.x(),
                *value_coords.y(),
                *token_coords.x(),
                *token_coords.y(),
            ],
        ));
    }

    // Serialize everything gathered and return it
    let mut metadata = vec![];
    zk_public_inputs.encode(&mut metadata)?;
    signature_pubkeys.encode(&mut metadata)?;

    Ok(metadata)
}

/// `process_instruction` function for `Money::TransferV1`
pub(crate) fn money_fee_process_instruction_v1(
    cid: ContractId,
    call_idx: u32,
    calls: Vec<ContractCall>,
) -> Result<Vec<u8>, ContractError> {
    if call_idx != 0 {
        msg!("[FeeV1] Error: call idx is not 0");
        return Err(MoneyError::CallIdxNonZero.into())
    }

    let self_ = &calls[call_idx as usize];
    let params: MoneyFeeParamsV1 = deserialize(&self_.data[1..])?;

    if params.inputs.len() < 1 {
        msg!("[FeeV1] Error: No inputs in the call");
        return Err(MoneyError::FeeMissingInputs.into())
    }

    // Access the necessary databases where there is information to
    // validate this state transition.
    let info_db = db_lookup(cid, MONEY_CONTRACT_INFO_TREE)?;
    let coins_db = db_lookup(cid, MONEY_CONTRACT_COINS_TREE)?;
    let nullifiers_db = db_lookup(cid, MONEY_CONTRACT_NULLIFIERS_TREE)?;
    let coin_roots_db = db_lookup(cid, MONEY_CONTRACT_COIN_ROOTS_TREE)?;

    // Accumulator for the value commitments.
    let mut valcom_total = pallas::Point::identity();

    // For now there's a minimum fee (0.0001), later on we'll make it dynamic.
    if params.fee_value < 10000 {
        msg!("[FeeV1] Error: Incorrect fee value: {}", params.fee_value);
        return Err(MoneyError::IncorrectFee.into())
    }

    // We can allow the faucet to do zero-fee transactions
    let Some(faucet_pubkeys) = db_get(info_db, &serialize(&MONEY_CONTRACT_FAUCET_PUBKEYS))? else {
        msg!("[FeeV1] Error: Missing faucet pubkeys from info db");
        return Err(MoneyError::MissingFaucetKeys.into())
    };
    let faucet_pubkeys: Vec<PublicKey> = deserialize(&faucet_pubkeys)?;

    let mut new_nullifiers = Vec::with_capacity(params.inputs.len());
    msg!("[FeeV1] Iterating over inputs");
    for (i, input) in params.inputs.iter().enumerate() {
        // The faucet can give any dummy input
        // TODO: Fix replay vuln
        if faucet_pubkeys.contains(&input.signature_public) {
            msg!("[FeeV1] Transaction is from a faucet, skip fee");
            valcom_total += input.value_commit;
            continue
        }

        if !db_contains_key(coin_roots_db, &serialize(&input.merkle_root))? {
            msg!("[FeeV1] Error: Merkle root not found in previous state (input {})", i);
            return Err(MoneyError::MerkleRootNotFound.into())
        }

        if new_nullifiers.contains(&input.nullifier) ||
            db_contains_key(nullifiers_db, &serialize(&input.nullifier))?
        {
            msg!("[FeeV1] Error: Duplicate nullifier found (input {})", i);
            return Err(MoneyError::DuplicateNullifier.into())
        }

        // TODO: Spend hook

        new_nullifiers.push(input.nullifier);
        valcom_total += input.value_commit;
    }

    let mut new_coins = Vec::with_capacity(params.outputs.len());
    for (i, output) in params.outputs.iter().enumerate() {
        if new_coins.contains(&Coin::from(output.coin)) ||
            db_contains_key(coins_db, &serialize(&output.coin))?
        {
            msg!("[FeeV1] Error: Duplicate coin found in output {}", i);
            return Err(MoneyError::DuplicateCoin.into())
        }

        new_coins.push(output.coin);
        valcom_total -= output.value_commit;
    }

    // Add the fee to the accumulator
    valcom_total -= pedersen_commitment_u64(params.fee_value, params.fee_value_blind);

    if valcom_total != pallas::Point::identity() {
        msg!("[FeeV1] Error: Value commitments do not result in identity");
        return Err(MoneyError::ValueMismatch.into())
    }

    // Verify that all token commitments are the same.
    let tokcom = pedersen_commitment_base(DARK_TOKEN_ID.inner(), params.token_blind);
    let mut failed_tokcom = params.inputs.iter().any(|x| x.token_commit != tokcom);
    failed_tokcom = failed_tokcom || params.outputs.iter().any(|x| x.token_commit != tokcom);

    if failed_tokcom {
        msg!("[FeeV1] Error: Token commitments do not match");
        return Err(MoneyError::TokenMismatch.into())
    }

    // At this point the state transition has passed. In case of the faucet,
    // the update will simply be empty.
    let update = MoneyFeeUpdateV1 {
        nullifiers: new_nullifiers,
        coins: new_coins,
        fee_value: params.fee_value,
    };
    let mut update_data = vec![];
    update_data.write_u8(MoneyFunction::FeeV1 as u8)?;
    update.encode(&mut update_data)?;
    Ok(update_data)
}

/// `process_update` function for `Money::FeeV1`
pub(crate) fn money_fee_process_update_v1(
    cid: ContractId,
    update: MoneyFeeUpdateV1,
) -> ContractResult {
    let info_db = db_lookup(cid, MONEY_CONTRACT_INFO_TREE)?;
    let coins_db = db_lookup(cid, MONEY_CONTRACT_COINS_TREE)?;
    let nullifiers_db = db_lookup(cid, MONEY_CONTRACT_NULLIFIERS_TREE)?;
    let coin_roots_db = db_lookup(cid, MONEY_CONTRACT_COIN_ROOTS_TREE)?;

    msg!("[FeeV1] Adding new nullifiers to the set");
    for nullifier in update.nullifiers {
        db_set(nullifiers_db, &serialize(&nullifier), &[])?;
    }

    msg!("[FeeV1] Adding new coins to the set");
    for coin in &update.coins {
        db_set(coins_db, &serialize(coin), &[])?;
    }

    msg!("[FeeV1] Adding new coins to the Merkle tree");
    let coins: Vec<_> = update.coins.iter().map(|x| MerkleNode::from(x.inner())).collect();
    merkle_add(info_db, coin_roots_db, &serialize(&MONEY_CONTRACT_COIN_MERKLE_TREE), &coins)?;

    let Some(current_fees) = db_get(info_db, &serialize(&MONEY_CONTRACT_PAID_FEES))? else {
        msg!("[FeeV1] Error: Did not find PAID_FEES in contract db");
        return Err(MoneyError::InternalError.into())
    };
    let current_fees: u64 = deserialize(&current_fees)?;

    let update_fees = update.fee_value + current_fees;
    msg!("[FeeV1] Paid fee {} (total {})", update.fee_value, update_fees);
    db_set(info_db, &serialize(&MONEY_CONTRACT_PAID_FEES), &serialize(&update_fees))?;

    Ok(())
}
