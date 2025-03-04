use reqwest::blocking::Client;
use reqwest::header::{COOKIE, USER_AGENT};
use url::Url;
use crate::config::C2_PROTOCOL;

pub struct Strike;

impl Strike {

    // 条件编译：HTTP 包装函数
    #[cfg(protocol = "http")]
    pub fn get_request(url: &str, cookie: &str, user_agent: &str) -> anyhow::Result<reqwest::blocking::Response> {
        http_get(url, cookie, user_agent).map_err(Into::into)
    }

    #[cfg(protocol = "http")]
    pub fn post_request(url: &str, cookie: &str, user_agent: &str, data: Vec<u8>) -> anyhow::Result<reqwest::blocking::Response> {
        http_post(url, cookie, user_agent, data).map_err(Into::into)
    }

    // 条件编译：HTTPS 包装函数
    #[cfg(protocol = "https")]
    pub fn get_request(url: &str, cookie: &str, user_agent: &str) -> anyhow::Result<reqwest::blocking::Response> {
        https_get(url, cookie, user_agent)
    }

    #[cfg(protocol = "https")]
    pub fn post_request(url: &str, cookie: &str, user_agent: &str, data: Vec<u8>) -> anyhow::Result<reqwest::blocking::Response> {
        https_post(url, cookie, user_agent, data)
    }
}

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
    let client = Client::new();
    client
        .post(url)
        .header(COOKIE, cookie)
        .header(USER_AGENT, user_agent)
        .body(data)
        .send()
}
// HTTPS GET 函数
pub fn https_get(url: &str, cookie: &str, user_agent: &str) -> anyhow::Result<reqwest::blocking::Response> {

    let client = Client::builder()
        .danger_accept_invalid_certs(true)
        .build()?;

    client
        .get(url)
        .header("Cookie", cookie)
        .header("User-Agent", user_agent)
        .send()
        .map_err(Into::into)
}

// HTTPS POST 函数
pub fn https_post(url: &str, cookie: &str, user_agent: &str, data: Vec<u8>) -> anyhow::Result<reqwest::blocking::Response> {
    let client = Client::builder()
        .danger_accept_invalid_certs(true)
        .build()?;

    client
        .post(url)
        .header("Cookie", cookie)
        .header("User-Agent", user_agent)
        .body(data)
        .send()
        .map_err(Into::into)
}
