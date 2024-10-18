use encoding_rs::{GBK, UTF_8};
use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use windows_sys::Win32::Globalization::GetACP;

/// 自动检测系统编码并将输入字节转换为 UTF-8 编码
pub fn convert_to_utf8_bytes(input: &[u8]) -> anyhow::Result<Vec<u8>, String> {
    // 调用 get_system_encoding() 获取当前系统编码
    let system_encoding = get_system_encoding();

    // 根据系统编码解码字节数据
    let decoded_str = match system_encoding.as_str() {
        "GBK" => {
            let (decoded, _, had_errors) = GBK.decode(input);
            if had_errors {
                return Err("Error decoding GBK".to_string());
            }
            decoded.into_owned()
        }
        "UTF-8" | _ => {
            let (decoded, _, had_errors) = UTF_8.decode(input);
            if had_errors {
                return Err("Error decoding UTF-8".to_string());
            }
            decoded.into_owned()
        }
    };

    // 将解码后的字符串转换为 UTF-8 编码的字节数组
    Ok(UTF_8.encode(&decoded_str).0.into())
}

/// 检测当前系统的字符集编码
fn get_system_encoding() -> String {
    #[cfg(windows)]
    {
        // Windows系统，通过 GetACP 获取当前代码页
        unsafe {
            let code_page = GetACP();
            match code_page {
                936 => "GBK".to_string(),       // 简体中文
                950 => "BIG5".to_string(),      // 繁体中文
                932 => "Shift-JIS".to_string(), // 日文
                949 => "EUC-KR".to_string(),    // 韩文
                _ => "UTF-8".to_string(),       // 默认 UTF-8
            }
        }
    }

    #[cfg(unix)]
    {
        // Unix系统中，通常为UTF-8，或者可以检查环境变量
        if let Ok(locale) = env::var("LC_CTYPE") {
            if locale.contains("GBK") {
                return "GBK".to_string();
            }
        }
        if let Ok(locale) = env::var("LANG") {
            if locale.contains("GBK") {
                return "GBK".to_string();
            }
        }
        "UTF-8".to_string() // 默认返回UTF-8
    }
}

pub fn to_wide_string(s: &str) -> Vec<u16> {
    OsStr::new(s).encode_wide().chain(Some(0)).collect()
}
