use dotenv::dotenv;
use std::env;

//--------------------------------------------------------------------------
// Settings
//--------------------------------------------------------------------------

#[derive(Clone)]
pub struct Settings {
    pub public_key_path: String,
    pub secret_key_path: String,
    pub client_id: String,
    pub client_secret: String,
    pub redirect_uri: String,
    pub oauth_uri: String,
    pub content_uri: String,
    pub profile_uri: String,
}

pub fn read_settings() -> Settings {
    dotenv().ok();

    let public_key_path: String = env::var("PUBLIC_KEY_PATH")
        .expect("PUBLIC_KEY_PATH required");
    let secret_key_path: String = env::var("SECRET_KEY_PATH")
        .expect("SECRET_KEY_PATH required");
    let client_id: String = env::var("CLIENT_ID")
        .expect("CLIENT_ID required");
    let redirect_uri: String = env::var("REDIRECT_URI")
        .expect("REDIRECT_URI required");
    let oauth_uri: String = env::var("OAUTH_URI")
        .expect("OAUTH_URI required");
    let content_uri: String = env::var("CONTENT_URI")
        .expect("CONTENT_URI required");
    let profile_uri: String = env::var("PROFILE_URI")
        .expect("PROFILE_URI required");
    let client_secret: String = env::var("CLIENT_SECRET")
        .expect("CLIENT_SECRET required");

    Settings {
        public_key_path: public_key_path,
        secret_key_path: secret_key_path,
        client_id: client_id,
        redirect_uri: redirect_uri,
        oauth_uri: oauth_uri,
        content_uri: content_uri,
        profile_uri: profile_uri,
        client_secret: client_secret,
    }
}
