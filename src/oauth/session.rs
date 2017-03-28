use rocket::http::{CookieJar, Cookie};

pub struct Session(pub CookieJar<'static>);

fn build_cookie(name: String, value: String) -> Cookie<'static> { 
    // It's oven time, baby
    Cookie::build(name, value)
        .domain("www.example.com")
        .path("/api")
        .http_only(true)
        .finish()
}

impl Session {

    pub fn new(key: &[u8]) -> Session {
        Session(CookieJar::new(key))
    }

    //----------------------------------------------------------------------
    // Accessors
    //----------------------------------------------------------------------

    #[inline]
    pub fn state(&self) -> String {
        let state_cookie = self.0.find("state").unwrap();
        state_cookie.value().to_string()
    }

    #[inline]
    pub fn code(&self) -> String {
        let code_cookie = self.0.find("code").unwrap();
        code_cookie.value().to_string()
    }

    //----------------------------------------------------------------------
    // Mutators
    //----------------------------------------------------------------------

    #[inline]
    fn set_state(&mut self, state: String) {
        self.0.add(build_cookie("state".to_string(), state));
    }

    #[inline]
    fn remove_state(&mut self) {
        self.0.remove(Cookie::named("state"));
    }

    #[inline]
    fn set_code(&mut self, code: String) {
        self.0.add(build_cookie("code".to_string(), code));
    }

    #[inline]
    fn set_scopes(&mut self, scopes: String) {
        self.0.add(build_cookie("scopes".to_string(), scopes));
    }

    #[inline]
    fn set_token_type(&mut self, token_type: String) {
        self.0.add(build_cookie("token_type".to_string(), token_type));
    }

    #[inline]
    fn set_token(&mut self, token: String) {
        self.0.add(build_cookie("token".to_string(), token));
    }
}
