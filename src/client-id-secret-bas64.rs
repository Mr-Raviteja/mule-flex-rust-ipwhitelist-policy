use proxy_wasm::traits::*;
use proxy_wasm::types::*;
use log::info;
use std::error::Error;
use serde::{Deserialize, Serialize};
use base64::{Engine as _, engine::general_purpose};


proxy_wasm::main! {{
    proxy_wasm::set_log_level(LogLevel::Trace);
    proxy_wasm::set_root_context(|_| -> Box<dyn RootContext> {
        Box::new(HttpConfigHeaderRoot {
            username: String::new(), password: String::new()
            
        })
    });
}}
fn decodeb64_string (inputstring : &String) -> Result< String, Box<dyn Error>>
{
    let utfbytes = general_purpose::STANDARD.decode(inputstring)?;
    let decodedstring = String::from_utf8( utfbytes)?;
    Ok(decodedstring) 
}
struct HttpConfigHeader {
    username: String,
    password : String
}

impl Context for HttpConfigHeader {}

impl HttpContext for HttpConfigHeader {
    fn on_http_request_headers(&mut self, _num_headers: usize, _end_of_stream: bool) -> Action {
        info!("on_http_request_headers new "); 

        for (name, value) in &self.get_http_request_headers() {
            info!("In WASM : # {}: {}", name, value);
        }

        if let Some(hostvalue) = self.get_http_request_header("Host") {
           info!("on_http_request_headers new HOST is {}", hostvalue);
           
        }

        if let Some(cid) = self.get_http_request_header("x-client-id") {

            info!(" got x user name {} ", cid);
            //let mut decoded_cid = String::new();

            let  decoded_cid = match  decodeb64_string(&cid) {
                Ok(decoded_string) => decoded_string,
                Err(err) => { 
                    info!("error happened while calling decodeb64_string {}",err); 
                    self.send_http_response(401, Vec::new(), None);
                    return Action::Pause  },
                
            };

            info!(" got decoded x user name {} ", decoded_cid);
            if let Some(csec) = self.get_http_request_header("x-client-secret") {
                     info!(" got x password {} ", csec);
                     //let mut decoded_cis = String::new();

                    let decoded_cis = match  decodeb64_string(&csec) {
                        Ok(decoded_string) => decoded_string,
                        Err(err) => { info!("error happened while calling decodeb64_string {}",err); self.send_http_response(401, Vec::new(), None);
                        return Action::Pause  },
                        
                    };
                    info!(" got decoded x user name {} ", decoded_cis);
                    let combined = decoded_cid + &decoded_cis;
                    let setting = self.username.clone() + &self.password.clone();

                    if setting == combined{
                        info!(" match found ");
                        return Action::Continue;
                    }
                    info!(" combined value {} not matching with configuration {} ", combined, setting);

            
            }
            else {
                info!("on_http_request_headers x-client-secret missing");
                self.send_http_response(401, Vec::new(), None);
                return Action::Pause   
            }
           
           
        }
        
        info!("on_http_request_headers x-client-id blocking");
        self.send_http_response(401, Vec::new(), None);
        Action::Pause   
    }

    fn on_http_request_body(&mut self, _body_size: usize, _end_of_stream: bool) -> Action {
        info!("on_http_request_body");
        if !_end_of_stream {
            // Wait -- we'll be called again when the complete body is buffered
            // at the host side.
            info!("on_http_request_body wait end of stream");
            return Action::Pause;
        }

        if let Some(body_bytes) = self.get_http_request_body(0, _body_size) {
            info!("on_http_request_body wait read body. bytes {}", _body_size);
            let body_str = String::from_utf8(body_bytes).unwrap();
            info!("on_http_request_body  body is {}", body_str);
        }
        info!("on_http_request_body exit");
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
     #[serde(alias = "user-name")]
     username: String,
     #[serde(alias = "password")]
     password: String


}

struct HttpConfigHeaderRoot {
    username: String,
    password : String

}

impl Context for HttpConfigHeaderRoot {}

impl RootContext for HttpConfigHeaderRoot {
    fn on_configure(&mut self, _: usize) -> bool {
        if let Some(config_bytes) = self.get_plugin_configuration() {
            let config:PolicyConfig = serde_json::from_slice(config_bytes.as_slice()).unwrap();
            self.username = config.username;
            self.password = config.password;
            info!("secret header is {} {} ",self.username, self.password);
            
        }
        true
    }
    
    fn create_http_context(&self, _: u32) -> Option<Box<dyn HttpContext>> {
        
          Some(Box::new(HttpConfigHeader {
            username: self.username.clone(), password : self.password.clone()
        }))
    }

    fn get_type(&self) -> Option<ContextType> {
        Some(ContextType::HttpContext)
    }
}
