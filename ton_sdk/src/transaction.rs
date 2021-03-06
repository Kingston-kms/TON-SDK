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

use crate::error::SdkError;
use crate::json_helper;
use crate::{Message, MessageId};
use crate::types::StringId;
use crate::node_client::NodeClient;
use crate::types::TRANSACTIONS_TABLE_NAME;
use ton_types::Result;

use futures::{Stream, StreamExt};
use ton_block::{TransactionProcessingStatus, AccStatusChange, ComputeSkipReason};
use serde::Deserialize;

#[derive(Deserialize, Default, Debug)]
#[serde(default)]
pub struct ComputePhase {
    pub compute_type: u8,
    #[serde(deserialize_with = "json_helper::deserialize_skipped_reason")]
    pub skipped_reason: Option<ComputeSkipReason>,
    pub exit_code: Option<i32>,
    pub success: Option<bool>
}

#[derive(Deserialize, Default, Debug)]
#[serde(default)]
pub struct StoragePhase {
    #[serde(deserialize_with = "json_helper::deserialize_acc_state_change")]
    pub status_change: AccStatusChange
}

#[derive(Deserialize, Default, Debug)]
#[serde(default)]
pub struct ActionPhase {
    pub success: bool,
    pub valid: bool,
    pub no_funds: bool,
    pub result_code: i32
}

pub type TransactionId = StringId;

#[derive(Deserialize, Default, Debug)]
#[serde(default)]
pub struct Transaction {
    pub id: TransactionId,
    #[serde(deserialize_with = "json_helper::deserialize_tr_state")]
    pub status: TransactionProcessingStatus,
    pub now: u32,
    pub in_msg: Option<MessageId>,
    pub out_msgs: Vec<MessageId>,
    pub aborted: bool,
    pub compute: ComputePhase,
    pub storage: Option<StoragePhase>,
    pub action: Option<ActionPhase>
}

// The struct represents performed transaction and allows to access their properties.
#[allow(dead_code)]
impl Transaction {

    // Asynchronously loads a Transaction instance or None if transaction with given id is not exists
    pub async fn load<'a>(client: &'a NodeClient, id: &TransactionId) -> Result<Option<Transaction>> {
        let value = client.load_record_fields(
            TRANSACTIONS_TABLE_NAME,
            &id.to_string(),
            TRANSACTION_FIELDS_ORDINARY).await?;

        if value == serde_json::Value::Null {
            Ok(None)
        } else {
            Ok(Some(serde_json::from_value(value)
                .map_err(|err| SdkError::InvalidData {
                    msg: format!("error parsing transaction: {}", err)
                })?))
        }
    }

    // Returns transaction's processing status
    pub fn status(&self) -> TransactionProcessingStatus {
        self.status
    }

    // Returns id of transaction's input message if it exists
    pub fn in_message_id(&self) -> Option<MessageId> {
        self.in_msg.clone()
    }

    // Asynchronously loads an instance of transaction's input message
    pub async fn load_in_message(&self, client: &NodeClient) -> Result<Option<Message>> {
        match self.in_message_id() {
            Some(m) => Message::load(client, &m).await,
            None => bail!(SdkError::InvalidOperation { msg: "transaction doesn't have inbound message".into() } )
        }
    }

    // Returns id of transaction's out messages if it exists
    pub fn out_messages_id(&self) -> &Vec<MessageId> {
        &self.out_msgs
    }

    // Returns message's identifier
    pub fn id(&self) -> TransactionId {
        // On client side id is ready allways. It is never be calculated, just returned.
        self.id.clone()
    }

    // Returns `aborted` flag
    pub fn is_aborted(&self) -> bool {
        self.aborted
    }

    // Asynchronously loads an instances of transaction's out messages
    pub fn load_out_messages<'a>(&self, client: &'a NodeClient) -> Result<impl Stream<Item = Result<Message>> + Send + 'a> {
        Ok(futures::stream::iter(self.out_messages_id().clone()).then(move |id| async move { 
            match Message::load(client, &id).await {
                Err(err) => Err(err),
                Ok(msg) => msg.ok_or(SdkError::NoData.into())
            }}))
    }
}

pub const TRANSACTION_FIELDS_ORDINARY: &str = r#"
    id
    aborted
    compute {
        compute_type
        skipped_reason
        exit_code
        success
    }
    storage {
       status_change 
    }
    in_msg
    now
    out_msgs
    status
"#;
