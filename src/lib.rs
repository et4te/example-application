#![feature(plugin, custom_derive)]
#![plugin(rocket_codegen)]

#[macro_use] extern crate serde_derive;

extern crate rocket;
extern crate rocket_contrib;
extern crate reqwest;
extern crate openssl;
extern crate rustc_serialize;
extern crate serde;
extern crate serde_json;
extern crate rand;
extern crate dotenv;

pub mod oauth;
pub mod controllers;
pub mod error;
