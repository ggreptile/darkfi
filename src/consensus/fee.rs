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

use crate::{tx::Transaction, Result};

/// Deterministically calculated fee for a single network transaction.
#[derive(Debug, Clone, Copy)]
pub struct Fee {
    /// Total gas used from all contract calls
    pub gas_used: u64,
    /// Amount of signatures verified
    pub signatures: usize,
    // TODO: Proofs, should be calculated from decoded zkas
    // pub proof_cost: usize,
}

impl Default for Fee {
    fn default() -> Self {
        Self { gas_used: 0, signatures: 0 }
    }
}

impl Fee {
    pub fn calculate(_tx: &Transaction) -> Result<u64> {
        Ok(10000)
    }
}
