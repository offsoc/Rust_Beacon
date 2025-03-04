use std::fs;

fn main() {
    // 读取 config.rs 文件内容
    let config_content = fs::read_to_string("src/config/mod.rs").expect("无法读取 config.rs");

    // 找到定义 C2_PROTOCOL 的行
    let protocol_line = config_content
        .lines()
        .find(|line| line.contains("C2_PROTOCOL"))
        .expect("config.rs 中未找到 C2_PROTOCOL 定义");

    // 提取 "http" 或 "https" 的值
    let protocol = protocol_line
        .split('"')
        .nth(1)
        .expect("C2_PROTOCOL 定义格式无效");

    // 根据 protocol 的值设置 cfg 标志
    if protocol == "http" {
        println!("cargo:rustc-cfg=protocol=\"http\"");
    } else if protocol == "https" {
        println!("cargo:rustc-cfg=protocol=\"https\"");
    } else {
        panic!("C2_PROTOCOL 无效：必须是 \"http\" 或 \"https\"");
    }
}