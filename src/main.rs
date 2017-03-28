#![feature(plugin, custom_derive)]
#![plugin(rocket_codegen)]

#[macro_use] extern crate serde_derive;

extern crate rocket;
extern crate rocket_contrib;
extern crate openssl;
extern crate serde;
extern crate serde_json;
extern crate rustc_serialize;
extern crate handlebars;
extern crate reqwest;
extern crate futures;
extern crate hyper;
extern crate tokio_core;
extern crate dotenv;
extern crate rand;

use rocket::http::{CookieJar};
use rocket::request::Request;
use handlebars::Handlebars;
use std::path::{Path};

pub mod oauth;
pub mod controllers;
pub mod error;

use oauth::settings::{self};
use oauth::flow::Flow;
use oauth::crypto::{self};

//--------------------------------------------------------------------------
// Templates
//--------------------------------------------------------------------------

pub struct HandlebarsState(pub Handlebars);

fn register_templates(handlebars: &mut Handlebars) {
    handlebars.register_template_file("main", &Path::new("./templates/main.html.hbs")).ok().unwrap();
}

//--------------------------------------------------------------------------
// Errors
//--------------------------------------------------------------------------

#[error(404)]
fn not_found(_: &Request) -> String {
    String::from("404 - Not found")
}

//--------------------------------------------------------------------------
// Start
//--------------------------------------------------------------------------

fn main() {
    let settings = settings::read_settings();
    let public_key = crypto::read_public_key(settings.clone()).unwrap();
    let _ = CookieJar::new(settings.client_secret.as_bytes());
    let mut handlebars = Handlebars::new();
    register_templates(&mut handlebars);
    let flow = Flow::new();

    rocket::ignite()
        // Routes
        .mount("/", routes![
            controllers::oauth::well_known,
        ])

        .mount("/api", routes![
            controllers::oauth::login,
            controllers::oauth::signup,
            controllers::oauth::best_choice,
            controllers::oauth::force_auth,
            controllers::oauth::oauth,
        ])

        // Shared state
        .manage(settings)
        .manage(public_key)
        .manage(flow)
        .manage(HandlebarsState(handlebars))

        // Errors
        .catch(errors![not_found])

        // Go
        .launch();
}
