/*
* Copyright 2018-2020 TON DEV SOLUTIONS LTD.
*
* Licensed under the SOFTWARE EVALUATION License (the "License"); you may not use
* this file except in compliance with the License.  You may obtain a copy of the
* License at: https://ton.dev/licenses
*
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific TON DEV software governing permissions and
* limitations under the License.
*/

use ton_sdk::Contract;
use futures::Stream;
use types::{ApiResult, ApiError};
use crypto::keys::{account_decode};
use client::ClientContext;

#[derive(Deserialize)]
#[allow(non_snake_case)]
pub(crate) struct LoadParams {
    pub address: String,
}

#[allow(non_snake_case)]
#[derive(Serialize, Deserialize)]
pub(crate) struct LoadResult {
    pub id: Option<String>,
    pub balanceGrams: Option<String>,
}

pub(crate) fn load(_context: &mut ClientContext, params: LoadParams) -> ApiResult<LoadResult> {
    let loaded = Contract::load(&account_decode(&params.address)?)
        .map_err(|err|ApiError::contracts_load_failed(err, &params.address))?
        .wait()
        .next();
    match loaded {
        Some(optional_contract_or_err) =>
            match optional_contract_or_err {
                Ok(optional_contract) =>
                    match optional_contract {
                        Some(contract) => make_result(contract),
                        None => Ok(EMPTY_RESULT)
                    },
                Err(err) => Err(ApiError::contracts_load_failed(err, &params.address))
            },
        None => Ok(EMPTY_RESULT)
    }
}

// Internals

const EMPTY_RESULT: LoadResult = LoadResult {
    id: None,
    balanceGrams: None,
};

fn make_result(contract: Contract) -> ApiResult<LoadResult> {
    Ok(LoadResult {
        id: contract.id().map(|id| id.to_hex_string()).ok(),
        balanceGrams: contract.balance_grams().map(|balance| balance.to_string()).ok(),
    })
}
