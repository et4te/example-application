
use rocket::Outcome;
use rocket::State;
use rocket::http::{Status, CookieJar, Cookie};
use rocket::request::{self, Request, FromRequest};
use rocket::response::{Redirect};
use rocket_contrib::JSON;
use reqwest;
use reqwest::header::{Headers, Bearer, Authorization};
use reqwest::StatusCode;
use oauth::settings::Settings;
use oauth::flow::Flow;
use oauth::crypto::PublicKey;
use oauth::*;
use serde_json;
use error::OAuthError;

fn build_cookie(name: String, value: String) -> Cookie<'static> {
    Cookie::build(name, value)
        .domain("www.example.com")
        .path("/api")
        .http_only(true)
        .finish()
}

//--------------------------------------------------------------------------
// Routes
//--------------------------------------------------------------------------

#[get("/login")]
pub fn login<'a>(settings: State<Settings>, flow: State<Flow>) -> JSON<OAuthResponse> {
    let settings = settings.inner();
    let flow = flow.inner();
    let info = build_signin_response(settings, flow);
    JSON(info)
}

#[get("/signup")]
pub fn signup<'a>(settings: State<Settings>, flow: State<'a, Flow>) -> JSON<OAuthResponse> {
    let settings = settings.inner();
    let flow = flow.inner();
    let info = build_signup_response(settings, flow);
    JSON(info)
}

#[get("/best_choice")]
pub fn best_choice<'a>(settings: State<Settings>, flow: State<'a, Flow>) -> JSON<OAuthResponse> {
    let settings = settings.inner();
    let flow = flow.inner();
    let info = build_best_choice_response(settings, flow);
    JSON(info)
}

#[derive(Serialize, Deserialize, FromForm)]
pub struct ForceAuthRequest {
    email: String,
}

#[get("/force_auth?<req>")]
pub fn force_auth<'a>(req: ForceAuthRequest, settings: State<'a, Settings>, flow: State<'a, Flow>) -> JSON<OAuthResponse> {
    let settings = settings.inner();
    let flow = flow.inner();
    let info = build_force_auth_response(&settings, flow, req.email);
    JSON(info)
}

//--------------------------------------------------------------------------
// Authorization
//--------------------------------------------------------------------------

pub struct Referer(String);

impl<'a, 'r> FromRequest<'a, 'r> for Referer {
    type Error = ();

    fn from_request(request: &'a Request<'r>) -> request::Outcome<Referer, ()> {
        let headers: Vec<_> = request.headers().get("Referer").collect();
        if headers.len() != 1 {
            return Outcome::Failure((Status::BadRequest, ()));
        }

        let referer = headers[0];

        return Outcome::Success(Referer(referer.to_string()))
    }
}

#[get("/oauth?<req>")]
pub fn oauth(req: OAuthRequest, referer: Referer, settings: State<Settings>, flow: State<Flow>, session: &CookieJar) -> Result<Redirect, OAuthError> {
    let referer = referer.0.clone();
    let settings = settings.inner();
    let flow = flow.inner();

    // Check for user finishing flow in a different browser, prompt for login.
    match req.error {
        Some(err) => {
            // Check for DifferentBrowserError
            println!("OAuthError = {}", err);
            Ok(Redirect::to("/?oauth_incomplete=true"))
        },

        None => {

            let state_cookie = session.find("state").unwrap();

            // The state (nonce) should exist in set of active flows and
            // the user should have a cookie with identical state.
            match flow.verify(req.clone(), state_cookie.value().to_owned()) {
                true => {
                    // Delete the state (nonce) from the session
                    let state = req.state.clone();

                    flow.remove(state.clone());
                    session.remove(state.clone());

                    // POST request for a token
                    let token_req = TokenRequest::new(settings, session);

                    let json = try!(serde_json::to_string(&token_req));

                    let client = try!(reqwest::Client::new());

                    // POST TokenRequest
                    let url = [settings.oauth_uri.clone(), "token".to_string()].join("/");
                    let mut rsp = try!(client.post(url.as_str()).body(json.as_str()).send());

                    let token_rsp: TokenResponse = try!(rsp.json());
                    let scopes = token_rsp.scopes.clone();
                    let token_type = token_rsp.token_type.clone();
                    let token = token_rsp.access_token.clone();

                    session.add(build_cookie("scopes".to_string(), scopes.join(" ")));
                    session.add(build_cookie("token_type".to_string(), token_type.clone()));
                    session.add(build_cookie("token".to_string(), token.clone()));

                    // GET request for authorization
                    let mut headers = Headers::new();
                    let bearer = Bearer {
                        token: token.to_owned()
                    };
                    headers.set(Authorization(bearer));

                    let url = [settings.profile_uri.clone(), "profile".to_string()].join("/");
                    let mut rsp = try!(client.get(url.as_str()).headers(headers).send());

                    // if status >= 400, return status + rsp
                    match rsp.status() {
                        &StatusCode::BadRequest => {
                            let json = try!(rsp.json());
                            return Err(OAuthError::UnknownError(json));
                        },

                        &StatusCode::Ok => {
                            let data: AccessResponse = try!(rsp.json());
                            session.add(build_cookie("email".to_string(), data.email.clone()));
                            session.add(build_cookie("uid".to_string(), data.uid.clone()));

                            if referer.contains("/iframe") {
                                Ok(Redirect::to("/iframe"))
                            } else {
                                Ok(Redirect::to("/"))
                            }
                        },

                        _ => {
                            let json = try!(rsp.json());
                            return Err(OAuthError::UnknownError(json));
                        },
                    }
                },

                false => {
                    match session.find("email") {
                        Some(email) => {
                            println!("session found email = {}", email.clone());
                            // User is logged in
                            Ok(Redirect::to("/"))
                        },

                        None => {
                            // 400 - error bad request
                            Err(OAuthError::HTTPError(Status::BadRequest))
                        }
                    }
                }
            }
        }
    }
}

//--------------------------------------------------------------------------
// Known Public Keys
//--------------------------------------------------------------------------

#[get("/.well-known/public-keys")]
fn well_known(public: State<PublicKey>) -> JSON<PublicKeyResponse> {
    let public_key = public.inner();
    JSON(PublicKeyResponse {
        kid: public_key.kid.clone(),
        _use: "sig".to_string(),
        kty: public_key.kty.clone(),
        n: public_key.n.clone(),
        e: public_key.e.clone(),
    })
}
