use crate::util::encode::convert_to_utf8_bytes;
use anyhow::{anyhow, bail};
use std::process::{Command, Stdio};

#[cfg(not(target_os = "windows"))]
pub fn os_system(cmd_line: &str) -> anyhow::Result<String> {
    let cmd_line_split: Vec<&str> = cmd_line.split_ascii_whitespace().collect();
    if cmd_line_split.len() < 1 {
        return Ok("".into());
    }
    let app = cmd_line_split[0];
    let mut command = Command::new(app);
    for arg in &cmd_line_split[1..] {
        command.arg(arg);
    }
    // throw error when app not found
    let output = command.output()?;
    // let (result, _, had_errors) = GBK.decode(&*output.stdout);
    let utf8_bytes = match convert_to_utf8_bytes(&output.stdout) {
        Ok(bytes) => bytes,
        Err(e) => {
            eprintln!("Error converting to UTF-8: {}", e);
            return Err(anyhow!("Error converting to UTF-8: {}", e));
        }
    };
    // let stdout = String::from_utf8_lossy(&*output.stdout);
    Ok(String::from_utf8_lossy(&utf8_bytes).to_string())
}
#[cfg(not(target_os = "windows"))]
pub fn os_system_anyway(cmd_line: &str) -> String {
    let res = os_system(cmd_line);
    if res.is_err() {
        return format!("{:?}", res.err().unwrap());
    }
    return res.unwrap();
}

#[cfg(not(target_os = "windows"))]
#[test]
fn test_os_system() {
    assert_eq!("program not found", os_system_anyway(&"whoami1"));
}
#[cfg(target_os = "windows")]
pub fn os_system(cmd_line: &str) -> anyhow::Result<String> {
    let cmd_line_split: Vec<&str> = if cfg!(windows) {
        cmd_line.split(',').collect()
    } else {
        cmd_line.split_ascii_whitespace().collect()
    };

    if cmd_line_split.is_empty() {
        return Ok("".into());
    }

    let app = cmd_line_split[0];
    let mut command = if cfg!(windows) {
        Command::new("cmd")
    } else {
        Command::new(app)
    };

    if cfg!(windows) {
        command.arg("/C").arg(app.replace("/", "\\"));
    } else {
        for arg in &cmd_line_split[1..] {
            command.arg(arg);
        }
    }

    let output = command
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()?;

    let utf8_bytes = match convert_to_utf8_bytes(&output.stdout) {
        Ok(bytes) => bytes,
        Err(e) => {
            eprintln!("Error converting to UTF-8: {}", e);
            return Err(anyhow!("Error converting to UTF-8: {}", e));
        }
    };
    let output_str = String::from_utf8_lossy(&*utf8_bytes);
    if !output.status.success() {
        bail!(
            "command failed with error code {}",
            output.status.code().unwrap_or(-1)
        );
    }
    let result = if cfg!(windows) {
        output_str.trim_end_matches("\r\n").to_owned()
    } else {
        output_str.to_string()
    };

    Ok(result)
}
