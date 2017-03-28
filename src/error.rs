
use rocket;
use reqwest;
use serde_json;
use openssl;
use std::io::{self};

#[derive(Debug)]
pub enum OAuthError {
    IOError(io::Error),
    JSONError(serde_json::Error),
    HTTPError(rocket::http::Status),
    HTTPClientError(reqwest::Error),
    OpenSSLError(openssl::error::ErrorStack),
    DifferentBrowserError(String),
    UnknownError(String),
}

impl From<io::Error> for OAuthError {
    fn from(err: io::Error) -> OAuthError {
        OAuthError::IOError(err)
    }
}

impl From<serde_json::Error> for OAuthError {
    fn from(err: serde_json::Error) -> OAuthError {
        OAuthError::JSONError(err)
    }
}

impl From<rocket::http::Status> for OAuthError {
    fn from(err: rocket::http::Status) -> OAuthError {
        OAuthError::HTTPError(err)
    }
}

impl From<openssl::error::ErrorStack> for OAuthError {
    fn from(err: openssl::error::ErrorStack) -> OAuthError {
        OAuthError::OpenSSLError(err)
    }
}

impl From<reqwest::Error> for OAuthError {
    fn from(err: reqwest::Error) -> OAuthError {
        OAuthError::HTTPClientError(err)
    }
}

impl From<String> for OAuthError {
    fn from(err: String) -> OAuthError {
        OAuthError::DifferentBrowserError(err)
    }
}
