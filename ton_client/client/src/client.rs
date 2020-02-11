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

use dispatch::DispatchTable;
use ::{JsonResponse, InteropContext};
use std::collections::HashMap;
use std::sync::{Mutex, MutexGuard};
use types::{ApiResult, ApiError};
use crate::serde_json::{Value, Map};

fn create_handlers() -> DispatchTable {
    let mut handlers = DispatchTable::new();
    crate::setup::register(&mut handlers);
    crate::crypto::register(&mut handlers);
    crate::contracts::register(&mut handlers);

    #[cfg(feature = "node_interaction")]
    crate::queries::register(&mut handlers);

    handlers
}

lazy_static! {
    static ref HANDLERS: DispatchTable = create_handlers();
}


fn sync_request(context: &mut ClientContext, method: String, params_json: String) -> JsonResponse {
    HANDLERS.sync_dispatch(context, method, params_json)
}

pub(crate) struct ClientContext {
    pub handle: u32
}

pub(crate) struct Client {
    next_context_handle: InteropContext,
    contexts: HashMap<InteropContext, ClientContext>,
}


lazy_static! {
    static ref CLIENT: Mutex<Client> = Mutex::new(Client::new());
}

impl Client {
    fn new() -> Self {
        Self {
            next_context_handle: 1,
            contexts: HashMap::new(),
        }
    }

    pub fn shared() -> MutexGuard<'static, Client> {
        CLIENT.lock().unwrap()
    }

    // Contexts

    pub fn create_context(&mut self) -> InteropContext {
        let handle = self.next_context_handle;
        self.next_context_handle = handle.wrapping_add(1);
        self.contexts.insert(handle, ClientContext {
            handle
        });
        handle
    }

    pub fn destroy_context(&mut self, handle: InteropContext) {
        self.required_context(handle).unwrap();
        if self.contexts.len() == 1 {
            self.json_sync_request(handle, "uninit".to_owned(), "{}".to_owned());
        }
        self.contexts.remove(&handle);
    }

    pub fn required_context(&mut self, context: InteropContext) -> ApiResult<&mut ClientContext> {
        self.contexts.get_mut(&context).ok_or(
            ApiError::invalid_context_handle(context)
        )
    }

    pub fn json_sync_request(&mut self, context: InteropContext, method_name: String, params_json: String) -> JsonResponse {
        if method_name == "?" {
            return self.debug_info();
        }
        let context = self.required_context(context);
        match context {
            Ok(context) => sync_request(context, method_name, params_json),
            Err(err) => JsonResponse::from_error(err)
        }
    }

    // Internals

    fn debug_info(&self) -> JsonResponse {
        let context_count = self.contexts.len();
        let mut info: Map<String, Value> = Map::new();
        info.insert("contextCount".into(), context_count.into());
        JsonResponse::from_result(Value::Object(info).to_string())
    }
}


