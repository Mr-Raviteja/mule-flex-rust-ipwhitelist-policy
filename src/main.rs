use proxy_wasm::traits::*;
use proxy_wasm::types::*;
use log::info;
use serde::{Deserialize, Serialize};



proxy_wasm::main! {{
    proxy_wasm::set_log_level(LogLevel::Trace);
    proxy_wasm::set_root_context(|_| -> Box<dyn RootContext> {
        Box::new(HttpConfigHeaderRoot {
            ip_address_local: vec![String::new(); 32]

        })
    });
}}

struct HttpConfigHeader {
    ip_address_local: Vec<String>
}

impl Context for HttpConfigHeader {}

impl HttpContext for HttpConfigHeader {
    fn on_http_request_headers(&mut self, _num_headers: usize, _end_of_stream: bool) -> Action {
        info!("on_http_request_headers");
        if let Some(_value) = self.get_http_request_header("x-forwarded-for") {
            info!(" before for self has {:?}",self.ip_address_local);
        for ip in self.ip_address_local {
           info!("for ip has {}",ip);
            info!(" after for self has {:?}",self.ip_address_local);
               if ip == _value {
                    info!("on_http_request_headers allowing {}",_value);
                    return Action::Continue;
               }
            }
        }
                info!("on_http_request_headers blocking");
                self.send_http_response(403, Vec::new(), None);
                Action::Pause


    }

    fn on_http_request_body(&mut self, _body_size: usize, _end_of_stream: bool) -> Action {
        info!("on_http_request_body");
        Action::Continue
    }

    fn on_http_response_headers(&mut self, _num_headers: usize, _end_of_stream: bool) -> Action {
        info!("on_http_response_headers");
        Action::Continue
    }

    fn on_http_response_body(&mut self, _body_size: usize, _end_of_stream: bool) -> Action {
        info!("on_http_response_body");
        Action::Continue
    }
}

#[derive(Serialize, Deserialize)]
struct PolicyConfig {
    #[serde(alias = "ipAddresses")]
    ip_addresses: Vec<String>
}

struct HttpConfigHeaderRoot {
    ip_address_local: Vec<String>
}

impl Context for HttpConfigHeaderRoot {}

impl RootContext for HttpConfigHeaderRoot {
    fn on_configure(&mut self, _: usize) -> bool {
        if let Some(config_bytes) = self.get_plugin_configuration() {
            let config:PolicyConfig = serde_json::from_slice(config_bytes.as_slice()).unwrap();
            self.ip_address_local = config.ip_addresses;
            info!("API Configuration");
            info!("ip header is {:?}",self.ip_address_local);
        }
        true
    }

    fn create_http_context(&self, _: u32) -> Option<Box<dyn HttpContext>> {
        Some(Box::new(HttpConfigHeader {
            ip_address_local: self.ip_address_local.clone(),
        }))
    }

    fn get_type(&self) -> Option<ContextType> {
        Some(ContextType::HttpContext)
    }
}

