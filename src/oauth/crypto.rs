use openssl::rsa::Rsa;
use openssl::bn::BigNumRef;
use openssl::types::{OpenSslType, OpenSslTypeRef};
use rustc_serialize::base64::{self, ToBase64};
use serde_json;
use serde;
use oauth::settings::Settings;
use error::OAuthError;
use std::fs::File;
use std::io::Read;

#[derive(Serialize, Deserialize)]
pub struct SecretKey {
    pub kty: String,
    pub n: String,
    pub e: String,
    pub d: String,
    pub p: String,
    pub q: String,
    pub dp: String,
    pub dq: String,
    pub qi: String,
}

pub trait Encodable where Self: serde::Serialize {
    fn encode(&self) -> Result<String, OAuthError> {
        let encoded = try!(serde_json::to_string(self));
        Ok(encoded)
    }
}

#[derive(Serialize, Deserialize)]
pub struct PublicKey {
    pub kid: String,
    pub kty: String,
    pub n: String,
    pub e: String,
}

impl Encodable for SecretKey {}
impl Encodable for PublicKey {}

pub fn read_public_key(settings: Settings) -> Result<PublicKey, OAuthError> {
    let mut file = try!(File::open(settings.public_key_path));
    let mut contents = String::new();
    let _ = try!(file.read_to_string(&mut contents));
    let result: PublicKey = try!(serde_json::from_str(&contents));
    Ok(result)
}

// Utility to convert BigNumRefs to base64
fn bn_to_base64(bn: &BigNumRef) -> String {
    bn.to_vec().to_base64(base64::URL_SAFE)
}

pub fn generate_keypair() -> Result<(SecretKey, PublicKey), OAuthError> {
    let rsa = try!(Rsa::generate(2048));
    let n = rsa.n().unwrap();
    let d = rsa.d().unwrap();
    let e = rsa.e().unwrap();
    let p = rsa.p().unwrap();
    let q = rsa.q().unwrap();

    unsafe {
        let rsa_ptr = rsa.as_ptr();
        if rsa_ptr.is_null() {
            Err(OAuthError::UnknownError("Error, RSA pointer was null".to_string()))
        } else {
            let dp = BigNumRef::from_ptr((*rsa_ptr).dmp1);
            let dq = BigNumRef::from_ptr((*rsa_ptr).dmq1);
            let qi = BigNumRef::from_ptr((*rsa_ptr).iqmp);

            let secret_key = SecretKey {
                kty: "RSA".to_string(),
                n: bn_to_base64(n.clone()),
                d: bn_to_base64(d),
                e: bn_to_base64(e.clone()),
                p: bn_to_base64(p),
                q: bn_to_base64(q),
                dp: bn_to_base64(dp),
                dq: bn_to_base64(dq),
                qi: bn_to_base64(qi),
            };

            let public_key = PublicKey {
                kid: "dev-1".to_string(),
                kty: "RSA".to_string(),
                n: bn_to_base64(n),
                e: bn_to_base64(e),
            };

            Ok((secret_key, public_key))
        }
    }
}

