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

use std::{collections::HashMap, io::Cursor};

use async_std::sync::{Arc, RwLock};
use darkfi_sdk::{
    crypto::{PublicKey, DAO_CONTRACT_ID, MONEY_CONTRACT_ID},
    pasta::pallas,
};
use darkfi_serial::{serialize, Decodable, Encodable, WriteExt};
use log::{error, info, warn};

use crate::{
    blockchain::{Blockchain, BlockchainOverlay, BlockchainOverlayPtr},
    runtime::vm_runtime::Runtime,
    tx::Transaction,
    util::time::Timestamp,
    zk::VerifyingKey,
    Error, Result, TxVerifyFailed,
};

use super::{fee::Fee, state::ConsensusState};

/// Atomic pointer to validator state
pub type ValidatorStatePtr = Arc<RwLock<ValidatorState>>;

/// The state of the validator node.
pub struct ValidatorState {
    /// Hot/Live data used by the consensus algorithm
    pub consensus: ConsensusState,
    /// Canonical (finalized) blockchain
    pub blockchain: Blockchain,
}

/// Configuration for initializing [`ValidatorState`]
pub struct ValidatorStateConfig {
    /// Bootstrap timestamp
    pub bootstrap_ts: Timestamp,
    /// Genesis timestamp
    pub genesis_ts: Timestamp,
    /// Genesis data
    pub genesis_data: blake3::Hash,
    /// Enable consensus participation
    pub enable_participation: bool,
    /// Whitelisted faucet pubkeys (testnet stuff)
    pub faucet_pubkeys: Vec<PublicKey>,
}

impl ValidatorState {
    pub async fn new(db: &sled::Db, config: ValidatorStateConfig) -> Result<ValidatorStatePtr> {
        info!(target: "consensus::validator", "Initializing ValidatorState");

        info!(target: "consensus::validator", "Initializing Blockchain");
        let blockchain = Blockchain::new(db, config.genesis_ts, config.genesis_data)?;

        info!(target: "consensus::validator", "Initializing ConsensusState");
        let consensus = ConsensusState::new(
            blockchain.clone(),
            config.bootstrap_ts,
            config.genesis_ts,
            config.genesis_data,
        )?;

        // =====================
        // NATIVE WASM CONTRACTS
        // =====================
        // This is the current place where native contracts are being deployed.
        // When the `Blockchain` object is created, it doesn't care whether it
        // already has the contract data or not. If there's existing data, it
        // will just open the necessary db and trees, and give back what it has.
        // This means that on subsequent runs our native contracts will already
        // be in a deployed state, so what we actually do here is a redeployment.
        // This kind of operation should only modify the contract's state in case
        // it wasn't deployed before (meaning the initial run). Otherwise, it
        // shouldn't touch anything, or just potentially update the db schemas or
        // whatever is necessary. This logic should be handled in the init function
        // of the actual contract, so make sure the native contracts handle this well.

        // The faucet pubkeys are pubkeys which are allowed to create clear inputs
        // in the Money contract.
        let money_contract_deploy_payload = serialize(&config.faucet_pubkeys);

        // The DAO contract uses an empty payload to deploy itself.
        let dao_contract_deploy_payload = vec![];

        let native_contracts = vec![
            (
                "Money Contract",
                *MONEY_CONTRACT_ID,
                include_bytes!("../contract/money/money_contract.wasm").to_vec(),
                money_contract_deploy_payload,
            ),
            (
                "DAO Contract",
                *DAO_CONTRACT_ID,
                include_bytes!("../contract/dao/dao_contract.wasm").to_vec(),
                dao_contract_deploy_payload,
            ),
        ];

        info!(target: "consensus::validator", "Deploying native WASM contracts");
        let blockchain_overlay = BlockchainOverlay::new(&blockchain)?;

        for nc in native_contracts {
            info!(target: "consensus::validator", "Deploying {} with ContractID {}", nc.0, nc.1);

            let mut runtime = Runtime::new(
                &nc.2[..],
                blockchain_overlay.clone(),
                nc.1,
                consensus.time_keeper.clone(),
            )?;

            runtime.deploy(&nc.3)?;

            info!(target: "consensus::validator", "Successfully deployed {}", nc.0);
        }

        // Write the changes to the actual chain db
        blockchain_overlay.lock().unwrap().overlay.lock().unwrap().apply()?;

        info!(target: "consensus::validator", "Finished deployment of native WASM contracts");

        // Create the actual state
        let state = Arc::new(RwLock::new(Self { blockchain, consensus }));

        Ok(state)
    }

    /// Validate WASM execution, signatures, and ZK proofs for a given [`Transaction`].
    async fn verify_transaction(
        &self,
        blockchain_overlay: BlockchainOverlayPtr,
        tx: &Transaction,
        verifying_keys: &mut HashMap<[u8; 32], HashMap<String, VerifyingKey>>,
    ) -> Result<()> {
        let tx_hash = tx.hash();
        info!(target: "consensus::validator", "Validating transaction {}", tx_hash);

        if tx.calls.len() < 2 {
            error!(target: "consensus::validator", "Transaction has less than 2 calls");
            return Err(TxVerifyFailed::MissingCalls.into())
        }

        // The first call in the transaction must be Money::Fee
        if tx.calls[0].contract_id != *MONEY_CONTRACT_ID && tx.calls[0].data[0] != 0x04 {
            error!(target: "consensus::validator", "Transaction call 0 is not Money::Fee");
            return Err(TxVerifyFailed::MissingFee.into())
        }

        // Tracker for the gas used
        let mut fee = Fee::default();

        // Table of public inputs used for ZK proof verification
        let mut zkp_table = vec![];
        // Table of public keys used for signature verification
        let mut sig_table = vec![];

        // Iterate over all non-fee calls to get the metadata
        for (idx, call) in tx.calls.iter().enumerate() {
            info!(target: "consensus::validator", "Executing contract call {}", idx);

            // Write the actual payload data
            let mut payload = vec![];
            payload.write_u32(idx as u32)?; // Call index
            tx.calls.encode(&mut payload)?; // Actual call data

            info!(target: "consensus::validator", "Instantiating WASM runtime");
            let wasm = self.blockchain.wasm_bincode.get(call.contract_id)?;

            let runtime = Runtime::new(
                &wasm,
                blockchain_overlay.clone(),
                call.contract_id,
                self.consensus.time_keeper.clone(),
            )?;

            info!(target: "consensus::validator", "Executing \"metadata\" call");
            let metadata = runtime.metadata(&payload)?;

            // Decode the metadata retrieved from the execution
            let mut decoder = Cursor::new(&metadata);

            // The tuple is (zkasa_ns, public_inputs)
            let zkp_pub: Vec<(String, Vec<pallas::Base>)> = Decodable::decode(&mut decoder)?;
            let sig_pub: Vec<PublicKey> = Decodable::decode(&mut decoder)?;
            // TODO: Make sure we've read all the bytes above.
            info!(target: "consensus::validator", "Successfully executed \"metadata\" call");

            // Here we'll look up verifying keys and insert them into the per-contract map.
            info!(target: "consensus::validator", "Performing VerifyingKey lookups from the sled db");
            for (zkas_ns, _) in &zkp_pub {
                let inner_vk_map = verifying_keys.get_mut(&call.contract_id.to_bytes()).unwrap();

                // TODO: This will be a problem in case of ::deploy, unless we force a different
                // namespace and disable updating existing circuit. Might be a smart idea to do
                // so in order to have to care less about being able to verify historical txs.
                if inner_vk_map.contains_key(zkas_ns.as_str()) {
                    continue
                }

                let (_, vk) = self.blockchain.contracts.get_zkas(
                    &self.blockchain.sled_db,
                    &call.contract_id,
                    zkas_ns,
                )?;

                inner_vk_map.insert(zkas_ns.to_string(), vk);
            }

            zkp_table.push(zkp_pub);
            sig_table.push(sig_pub);

            // After getting the metadata, we run the "exec" function with the same runtime
            // and the same payload.
            info!(target: "consensus::validator", "Executing \"exec\" call");
            let state_update = runtime.exec(&payload)?;
            info!(target: "consensus::validator", "Successfully executed \"exec\" call");

            // If that was successful, we apply the state update in the ephemeral overlay.
            info!(target: "consensus::validator", "Executing \"apply\" call");
            runtime.apply(&state_update)?;
            info!(target: "consensus::validator", "Successfully executed \"apply\" call");

            // We ran ::metadata, ::exec, and ::apply for a single call. We fetch the gas
            // used here, and note it down in the `Fee` struct. If this call fails, that
            // means the gas was exhausted, although that should also happen on ::exec or
            // ::metadata as well. Redundancy is ok.
            fee.gas_used += runtime.gas_used()?;

            // At this point we're done with the call and move on to the next one.
        }

        // When we're done looping and executing over the tx's contract calls, we now
        // move on with verification. First we verify the signatures as that's cheaper,
        // and then finally we verify the ZK proofs.
        info!(target: "consensus::validator", "Verifying signatures for transaction {}", tx_hash);
        if sig_table.len() != tx.signatures.len() {
            error!(target: "consensus::validator", "Incorrect number of signatures in tx {}", tx_hash);
            return Err(TxVerifyFailed::MissingSignatures.into())
        }

        // Note down how many signatures we have to verify
        fee.signatures = tx.signatures.len();

        // TODO: Go through the ZK circuits that have to be verified and account for the opcodes.
        // TODO: Verify that the fee paid is enough to cover used gas and verification

        if let Err(e) = tx.verify_sigs(sig_table) {
            error!(target: "consensus::validator", "Signature verification for tx {} failed: {}", tx_hash, e);
            return Err(TxVerifyFailed::InvalidSignature.into())
        }

        info!(target: "consensus::validator", "Signature verification successful");

        info!(target: "consensus::validator", "Verifying ZK proofs for transaction {}", tx_hash);
        if let Err(e) = tx.verify_zkps(verifying_keys, zkp_table).await {
            error!(target: "consensus::validator", "ZK proof verification for tx {} failed: {}", tx_hash, e);
            return Err(TxVerifyFailed::InvalidZkProof.into())
        }

        info!(target: "consensus::validator", "ZK proof verification successful");
        info!(target: "consensus::validator", "Transaction {} verified successfully", tx_hash);

        Ok(())
    }

    /// Validate a set of [`Transaction`] in sequence and apply them if all are valid.
    /// In case any of the transactions fail, they will be returned to the caller.
    /// The function takes a boolean called `write` which tells it to actually write
    /// the state transitions to the database.
    pub async fn verify_transactions(&self, txs: &[Transaction], write: bool) -> Result<()> {
        info!(target: "consensus::validator", "Verifying {} transactions", txs.len());

        info!(target: "consensus::validator", "Instantiating BlockchainOverlay");
        let blockchain_overlay = BlockchainOverlay::new(&self.blockchain)?;

        // Tracker for failed txs
        let mut erroneous_txs = vec![];

        // Map of ZK proof verifying keys for the current transaction batch
        let mut vks: HashMap<[u8; 32], HashMap<String, VerifyingKey>> = HashMap::new();

        // Initialize the map
        for tx in txs {
            for call in &tx.calls {
                vks.insert(call.contract_id.to_bytes(), HashMap::new());
            }
        }

        // Iterate over transactions and attempt to verify them
        for tx in txs {
            if let Err(e) = self.verify_transaction(blockchain_overlay.clone(), tx, &mut vks).await
            {
                warn!(target: "consensus::validator", "Transaction verification failed: {}", e);
                erroneous_txs.push(tx.clone());
                // FIXME: TODO: Revert the blockchain overlay to the previous state.
            }
        }

        let lock = blockchain_overlay.lock().unwrap();
        let overlay = lock.overlay.lock().unwrap();
        if !erroneous_txs.is_empty() {
            warn!(target: "consensus::validator", "Erroneous transactions found in set");
            overlay.purge_new_trees()?;
            return Err(TxVerifyFailed::ErroneousTxs(erroneous_txs).into())
        }

        if !write {
            info!(target: "consensus::validator", "Skipping apply of state updates because write=false");
            overlay.purge_new_trees()?;
            return Ok(())
        }

        info!(target: "consensus::validator", "Applying overlay changes");
        overlay.apply()?;
        Ok(())
    }

    /// Attempt to append the given transaction into the mempool.
    pub async fn append_tx(&mut self, tx: &Transaction) -> Result<()> {
        let tx_hash = tx.hash();
        info!(target: "consensus::validator", "Attempting to append transaction {} to mempool", tx_hash);

        if self.blockchain.transactions.contains(&tx_hash)? {
            error!(target: "consensus::validator", "append_tx(): Transaction already seen in the blockchain");
            return Err(Error::TransactionAlreadySeen)
        }

        if self.blockchain.pending_txs.contains(&tx_hash)? {
            error!(target: "consensus::validator", "append_tx(): Transaction already in mempool");
            return Err(Error::TransactionAlreadySeen)
        }

        info!(target: "consensus::validator", "append_tx(): Executing state transition");
        if let Err(e) = self.verify_transactions(&[tx.clone()], false).await {
            error!(target: "consensus::validator", "append_tx(): Transaction verification failed");
            return Err(e)
        }

        info!(target: "consensus::validator", "append_tx(): Executed successfully. Appending...");
        if let Err(e) = self.blockchain.add_pending_txs(&[tx.clone()]) {
            error!(target: "consensus::validator", "append_tx(): Failed to append tx to mempool: {}", e);
            return Err(e)
        }

        info!(target: "consensus::validator", "append_tx(): {} appended successfully", tx_hash);
        Ok(())
    }
}
