use reqwest::header::{COOKIE, USER_AGENT};

pub struct Strike();
impl Strike {
    pub fn http_get(
        url: &str,
        cookie: &str,
        user_agent: &str,
    ) -> anyhow::Result<reqwest::blocking::Response, reqwest::Error> {
        let client = reqwest::blocking::Client::new();
        client
            .get(url)
            .header(COOKIE, cookie)
            .header(USER_AGENT, user_agent)
            .send()
    }

    pub fn http_post(
        url: &str,
        cookie: &str,
        user_agent: &str,
        data: Vec<u8>,
    ) -> anyhow::Result<reqwest::blocking::Response, reqwest::Error> {
        let client = reqwest::blocking::Client::new();
        client
            .post(url)
            .header(COOKIE, cookie)
            .header(USER_AGENT, user_agent)
            .body(data)
            .send()
    }
}
