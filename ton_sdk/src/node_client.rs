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

use crate::{NodeClientConfig, TimeoutsConfig};
use crate::error::SdkError;
use graphite::client::GqlClient;
use graphite::types::{VariableRequest};
use futures::{TryFutureExt, Stream, StreamExt};
use serde_json::Value;
use reqwest::{ClientBuilder, RedirectPolicy, StatusCode};
use reqwest::header::LOCATION;
use ton_types::{error, Result};

#[derive(Serialize, Deserialize)]
pub enum SortDirection {
    #[serde(rename = "ASC")]
    Ascending,
    #[serde(rename = "DESC")]
    Descending
}

#[derive(Serialize, Deserialize)]
pub struct OrderBy {
    path: String,
    direction: SortDirection
}

#[derive(Debug, Clone, Serialize)]
pub struct MutationRequest {
    pub id: String,
    pub body: String
}

pub struct NodeClient {
    client: Option<GqlClient>,
    timeouts: TimeoutsConfig
}

impl NodeClient {

    fn check_redirect(address: &str) -> Result<Option<String>> {
        let client = ClientBuilder::new()
            .redirect(RedirectPolicy::none())
            .build()
            .map_err(|err| SdkError::InternalError { msg: format!("Can not build test request: {}", err) } )?;
    
        let result = client.get(address).send();
    
        match result {
            Ok(result) => {
                if result.status() == StatusCode::PERMANENT_REDIRECT {
                    let address = result
                        .headers()
                        .get(LOCATION)
                        .ok_or(SdkError::NetworkError { msg: "Missing location field in redirect response".to_owned() } )?
                        .to_str()
                        .map_err(|err| SdkError::NetworkError { msg: format!("Can not cast redirect location to string: {}", err) } )?
                        .to_owned();
    
                    Ok(Some(address))
                } else {
                    Ok(None)
                }
            },
            Err(err) => bail!(SdkError::NetworkError { msg: format!("Can not send test request: {}", err) } )
        }
    }

    fn expand_address(base_url: String) -> (String, String) {
        let base_url =  if  base_url.starts_with("http://") ||
                            base_url.starts_with("https://")
        {
            base_url
        } else {
            format!("https://{}", base_url)
        };
    
        let queries_url = format!("{}/graphql", base_url);
    
        let subscriptions_url = if queries_url.starts_with("https://") {
            queries_url.replace("https://", "wss://")
        } else {
            queries_url.replace("http://", "ws://")
        };

        (queries_url, subscriptions_url)
    }
    
    // Globally initializes client with server address
    pub fn new(config: NodeClientConfig) -> Result<NodeClient> {
        let client = if let Some(base_url) = config.base_url {
            let (mut queries_server, mut subscriptions_server) = Self::expand_address(base_url);
            if let Some(redirected) = Self::check_redirect(&queries_server)? {
                queries_server = redirected.clone();
                subscriptions_server = redirected
                    .replace("https://", "wss://")
                    .replace("http://", "ws://");
            }
            Some(GqlClient::new(&queries_server, &subscriptions_server)?)
        } else {
            None
        };

        Ok(NodeClient {
            client,
            timeouts: config.timeouts.unwrap_or_default()
        })
    }

    pub fn timeouts(&self) -> &TimeoutsConfig {
        &self.timeouts
    }
    
    // Returns Stream with updates database fileds by provided filter
    pub fn subscribe(&self, table: &str, filter: &str, fields: &str)
        -> Result<impl Stream<Item=Result<Value>> + Send> {
    
        let request = Self::generate_subscription(table, filter, fields)?;
    
        let closure_table = table.to_owned();

        let client = self.client.as_ref().ok_or(SdkError::SdkNotInitialized)?;
        let stream = client.subscribe(request)?
            .map(move |result| {
                    match result {
                        Err(err) => Err(error!(err).into()),
                        Ok(value) => {
                            // try to extract the record value from the answer
                            let record_value = &value["payload"]["data"][&closure_table];
                            
                            if record_value.is_null() {
                                Err(error!(SdkError::InvalidData {
                                    msg: format!("Invalid subscription answer: {}", value)
                                }).into())
                            } else {
                                Ok(record_value.clone())
                            }
                        }
                    }
                }
            );

        Ok(stream)
    }
    
    // Returns Stream with required database record fields
    pub async fn load_record_fields(&self, table: &str, record_id: &str, fields: &str)
        -> Result<Value> {
        let value = self.query(
            table,
            &format!("{{ \"id\": {{\"eq\": \"{record_id}\" }} }}", record_id=record_id),
            fields,
            None,
            None,
            None).await?;
        
        Ok(value[0].clone())
    }
    
    // Returns Stream with GraphQL query answer 
    pub async fn query(
        &self,
        table: &str,
        filter: &str,
        fields: &str,
        order_by: Option<OrderBy>,
        limit: Option<u32>,
        timeout: Option<u32>
    ) -> Result<Value> {
        let query = Self::generate_query_var(table, filter, fields, order_by, limit, timeout)?;

        let client = self.client.as_ref().ok_or(SdkError::SdkNotInitialized)?;
        let result = client.query_vars(query).await?;
        
        // try to extract the record value from the answer
        let records_array = &result["data"][&table];
        if records_array.is_null() {
            Err(SdkError::InvalidData { msg: format!("Invalid query answer: {}", result) }.into())
        } else {
            Ok(records_array.clone())
        }
    }
    
    // Executes GraphQL query, waits for result and returns recieved value
    pub async fn wait_for(&self, table: &str, filter: &str, fields: &str, timeout: Option<u32>)
        -> Result<Value>
    {
        let value = self.query(
            table,
            filter,
            fields,
            None,
            None,
            timeout.or(Some(self.timeouts.wait_for_timeout))).await?;

        if !value[0].is_null() {
            Ok(value[0].clone())
        } else {
            Err(SdkError::WaitForTimeout.into())
        }
    }
    
    fn generate_query_var(
        table: &str,
        filter: &str,
        fields: &str,
        order_by: Option<OrderBy>,
        limit: Option<u32>,
        timeout: Option<u32>
    ) -> Result<VariableRequest> {
        let mut scheme_type = (&table[0 .. table.len() - 1]).to_owned() + "Filter";
        scheme_type[..1].make_ascii_uppercase();
    
        let mut query = format!(
            r#"query {table}
            ($filter: {scheme_type}, $orderBy: [QueryOrderBy], $limit: Int, $timeout: Float)
            {{ 
                {table}(filter: $filter, orderBy: $orderBy, limit: $limit, timeout: $timeout)
                {{ {fields} }}
            }}"#,
            table=table,
            scheme_type=scheme_type,
            fields=fields
        );
        query = query.split_whitespace().collect::<Vec<&str>>().join(" ");
    
        let variables = json!({
            "filter" : serde_json::from_str::<Value>(filter)?,
            "orderBy": order_by,
            "limit": limit,
            "timeout": timeout
        });
    
        let variables = variables.to_string().split_whitespace().collect::<Vec<&str>>().join(" ");
    
        Ok(VariableRequest::new(query, Some(variables)))
    }
    
    fn generate_subscription(table: &str, filter: &str, fields: &str) -> Result<VariableRequest> {
        let mut scheme_type = (&table[0 .. table.len() - 1]).to_owned() + "Filter";
        scheme_type[..1].make_ascii_uppercase();
    
        let query = format!("subscription {table}($filter: {type}) {{ {table}(filter: $filter) {{ {fields} }} }}",
            type=scheme_type,
            table=table,
            fields=fields);
        let query = query.split_whitespace().collect::<Vec<&str>>().join(" ");
    
        let variables = json!({
            "filter" : serde_json::from_str::<Value>(filter)?
        });
        let variables = variables.to_string().split_whitespace().collect::<Vec<&str>>().join(" ");
    
        Ok(VariableRequest::new(query, Some(variables)))
    }
    
    fn generate_post_mutation(requests: &[MutationRequest]) -> Result<VariableRequest> {
        let query = "mutation postRequests($requests:[Request]){postRequests(requests:$requests)}".to_owned();
        let variables = json!({
            "requests": serde_json::to_value(requests)?
        }).to_string();
    
        Ok(VariableRequest::new(query, Some(variables)))
    }
    
    // Sends message to node
    pub async fn send_message(&self, key: &[u8], value: &[u8]) -> Result<()> {
        let request = MutationRequest {
            id: base64::encode(key),
            body: base64::encode(value)
        };

        let client = self.client.as_ref().ok_or(SdkError::SdkNotInitialized)?;
        client.query_vars(Self::generate_post_mutation(&[request])?)
            .map_err(|_| SdkError::NetworkError {
                    msg: "Post message error: server did not responded".to_owned()
                }.into())
            .map_ok(|_| ())
            .await
    }    
}
