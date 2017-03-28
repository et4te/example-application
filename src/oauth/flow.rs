use rustc_serialize::base64::{self, ToBase64};
use std::collections::HashMap;
use rand::{self, Rng};
use std::sync::{Arc, Mutex};
use super::OAuthRequest;

pub struct Flow(pub Arc<Mutex<HashMap<String, bool>>>);

// Generate a random string (32-bytes)
pub fn random_string() -> String {
    let r: String = rand::thread_rng()
        .gen_iter::<char>()
        .take(32)
        .collect();
    r.as_bytes().to_base64(base64::URL_SAFE)
}

impl Flow {

    pub fn new() -> Flow {
        let flow = Arc::new(Mutex::new(HashMap::<String, bool>::new()));
        Flow(flow)
    }

    pub fn find(&self, nonce: String) -> bool {
        let data = self.0.lock().unwrap();
        match data.get(&nonce) {
            Some(_) => true,
            None => false,
        }
    }

    // Generates a unique persistent nonce
    pub fn generate_persistent_nonce(&self) -> String {
        let r = random_string();
        let mut data = self.0.lock().unwrap();
        let _ = data.insert(r.clone(), true).unwrap();
        r
    }

    // Deletes nonce from shared state
    pub fn remove(&self, nonce: String) -> bool {
        let mut data = self.0.lock().unwrap();
        data.remove(&nonce).unwrap()
    }

    // Verifies nonce against self / client / session state
    pub fn verify(&self, req: OAuthRequest, nonce: String) -> bool {
        match req.code {
            Some(_) => {
                let data = self.0.lock().unwrap();
                match data.get(&nonce) {
                    Some(_) => req.state == nonce,
                    None => false,
                }
            },

            None => false,
        }
    }
}
