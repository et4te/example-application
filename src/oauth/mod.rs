pub mod settings;
pub mod flow;
pub mod crypto;

use rocket::http::{CookieJar};
use self::settings::Settings;
use self::flow::Flow;

//--------------------------------------------------------------------------
// API
//--------------------------------------------------------------------------

pub fn build_signin_response<'a>(settings: &'a Settings, flow: &'a Flow) -> OAuthResponse {
    OAuthResponse::new(settings, flow)
        .set_action("signin".to_string())
}

pub fn build_signup_response<'a>(settings: &'a Settings, flow: &'a Flow) -> OAuthResponse {
    OAuthResponse::new(settings, flow)
        .set_action("signup".to_string())
}

pub fn build_best_choice_response<'a>(settings: &'a Settings, flow: &'a Flow) -> OAuthResponse {
    OAuthResponse::new(settings, flow)
}

pub fn build_force_auth_response<'a>(settings: &'a Settings, flow: &'a Flow, email: String) -> OAuthResponse {
    OAuthResponse::new(settings, flow)
        .set_action("force_auth".to_string())
        .set_email(email.clone())
}

//--------------------------------------------------------------------------
// OAuthRequest
//--------------------------------------------------------------------------

#[derive(Deserialize, FromForm, Clone)]
pub struct OAuthRequest {
    pub state: String,
    pub code: Option<String>,
    pub error: Option<String>,
}

//--------------------------------------------------------------------------
// OAuthResponse
//--------------------------------------------------------------------------

#[derive(Serialize, Deserialize)]
pub struct OAuthResponse {
    pub state: String,
    pub action: Option<String>,
    pub client_id: String,
    pub email: Option<String>,
    pub scope: Option<Vec<String>>,
    pub redirect_uri: String,
    pub oauth_uri: String,
    pub content_uri: String,
}

impl OAuthResponse {

    pub fn new(settings: &Settings, flow: &Flow) -> OAuthResponse {
        //let mut flow = flow.0.get_mut().unwrap();
        let nonce = flow.generate_persistent_nonce();
        OAuthResponse {
            state: nonce,
            action: None,
            client_id: settings.client_id.clone(),
            email: None,
            scope: None,
            redirect_uri: settings.redirect_uri.clone(),
            oauth_uri: settings.oauth_uri.clone(),
            content_uri: settings.content_uri.clone(),
        }
    }

    #[inline]
    pub fn state(&self) -> String {
        self.state.clone()
    }

    #[inline]
    pub fn action(&self) -> Option<String> {
        self.action.clone()
    }

    #[inline]
    pub fn email(&self) -> Option<String> {
        self.email.clone()
    }

    #[inline]
    pub fn scope(&self) -> Option<Vec<String>> {
        self.scope.clone()
    }

    #[inline]
    pub fn set_action<'a>(mut self, action: String) -> OAuthResponse {
        self.action = Some(action);
        self
    }

    #[inline]
    pub fn set_email<'a>(mut self, email: String) -> OAuthResponse {
        self.email = Some(email);
        self
    }

    #[inline]
    pub fn set_scope<'a>(mut self, scope: Vec<String>) -> OAuthResponse {
        self.scope = Some(scope);
        self
    }
}

//--------------------------------------------------------------------------
// TokenRequest
//--------------------------------------------------------------------------

#[derive(Serialize, Deserialize)]
pub struct TokenRequest {
    pub code: String,
    pub client_id: String,
    pub client_secret: String,
}

impl TokenRequest {
    pub fn new(settings: &Settings, session: &CookieJar) -> TokenRequest {
        let cookie = session.find("code").unwrap();
        TokenRequest {
            code: cookie.value().to_string(),
            client_id: settings.client_id.clone(),
            client_secret: settings.client_secret.clone(),
        }
    }
}

//--------------------------------------------------------------------------
// TokenResponse
//--------------------------------------------------------------------------

#[derive(Serialize, Deserialize)]
pub struct TokenResponse {
    pub scopes: Vec<String>,
    pub token_type: String,
    pub access_token: String,
}

//--------------------------------------------------------------------------
// Access Response
//--------------------------------------------------------------------------

#[derive(Serialize, Deserialize)]
pub struct AccessResponse {
    pub uid: String,
    pub email: String,
}

//------------------------------------------------------------------------------
// Public Key Response
//------------------------------------------------------------------------------

#[derive(Serialize, Deserialize)]
pub struct PublicKeyResponse {
    pub kid: String,
    #[serde(rename = "use")]
    pub _use: String,
    pub kty: String,
    pub n: String,
    pub e: String,
}

