#[macro_use] extern crate serde_derive;

extern crate rustc_serialize;
extern crate openssl;
extern crate dotenv;
extern crate serde;
extern crate serde_json;

use super::oauth::crypto::{self};
use rustc_serialize::base64::{self, ToBase64};
use std::path::Path;
use dotenv::dotenv;
use std::fs::File;
use std::io::Write;
use std::env;

// Using a path from the config generates JWKs
fn main() {
    dotenv().ok();

    let public_key_path: String = env::var("PUBLIC_KEY_PATH")
        .expect("PUBLIC_KEY_PATH required");
    let secret_key_path: String = env::var("SECRET_KEY_PATH")
        .expect("SECRET_KEY_PATH required");

    let public_key_path = Path::new(public_key_path.as_str());
    let secret_key_path = Path::new(secret_key_path.as_str());

    println!("Running generate_keys ...");
    println!("PUBLIC_KEY_PATH = {:?}", public_key_path.clone());
    println!("SECRET_KEY_PATH = {:?}", secret_key_path.clone());

    if secret_key_path.exists() {
        println!("A secret key has already been generated for this service.")
    } else {
        let (secret_key, public_key) = crypto::generate_keypair();

        let secret_key_json = secret_key.encode().unwrap();
        let public_key_json = public_key.encode().unwrap();

        let mut secret_key_file = File::create(secret_key_path)
            .expect("Unable to create secret_key file");
        let mut public_key_file = File::create(public_key_path)
            .expect("Unable to create public_key file");

        secret_key_file.write_all(secret_key_json.as_bytes())
            .expect("Unable to write JSON data to secret key file");
        public_key_file.write_all(public_key_json.as_bytes())
            .expect("Unable to write JSON data to public_key file");

        println!("Generated secret key = {}", secret_key_json);
        println!("Generated public key = {}", public_key_json);

        println!("Success");
    }
}

