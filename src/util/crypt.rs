use std::vec;

use crypto::{
    aes::{self},
    buffer::{BufferResult, ReadBuffer, WriteBuffer},
    symmetriccipher,
};
use hmac::{Hmac, Mac};
use sha2::Sha256;
type HmacSha256 = Hmac<Sha256>;

/// hmacSha256, only use first 16 bytes
pub fn hmac_hash(key: &[u8], input: &[u8]) -> [u8; 16] {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC can take key of any size");
    mac.update(input);
    let result = mac.finalize();
    let mut hash = vec![];
    let code_bytes = result.into_bytes();
    hash.extend_from_slice(&code_bytes);
    hash[..16].try_into().unwrap()
}

#[test]
fn test_hmac_hash() {
    let hash = hmac_hash(b"ABC", b"test");
    assert_eq!(
        hash,
        hex::decode("998dfeb844cb6867f421e346640f47cabf3e34c4ec1b6957d56cdd7961510f82").unwrap()
            [..16]
    );
}

pub fn aes_decrypt(
    encrypted_data: &[u8],
    key: &[u8],
    iv: &[u8],
) -> Result<Vec<u8>, symmetriccipher::SymmetricCipherError> {
    let mut decryptor = aes::cbc_decryptor(
        aes::KeySize::KeySize128,
        key,
        iv,
        crypto::blockmodes::NoPadding,
    );

    let mut final_result = Vec::<u8>::new();
    let mut read_buffer = crypto::buffer::RefReadBuffer::new(encrypted_data);
    let mut buffer = [0; 4096];
    let mut write_buffer = crypto::buffer::RefWriteBuffer::new(&mut buffer);

    loop {
        let result = decryptor
            .decrypt(&mut read_buffer, &mut write_buffer, true)
            .unwrap();
        final_result.extend(
            write_buffer
                .take_read_buffer()
                .take_remaining()
                .iter()
                .map(|&i| i),
        );
        match result {
            BufferResult::BufferUnderflow => break,
            BufferResult::BufferOverflow => {}
        }
    }
    Ok(final_result)
}

#[test]
fn test_aes_encrypt() {
    let key = b"abcdefghijklmnop";
    let iv = b"abcdefghijklmnop";
    let output_encrypt = aes_encrypt("ABC".as_bytes(), key, iv).unwrap();
    assert_eq!(
        output_encrypt,
        [91, 207, 110, 243, 74, 180, 98, 107, 76, 154, 90, 244, 207, 185, 180, 167]
    );
    let output_encrypt = aes_encrypt("ABC".repeat(10).as_bytes(), key, iv).unwrap();
    assert_eq!(
        output_encrypt,
        [
            211, 115, 4, 183, 48, 173, 196, 20, 144, 214, 116, 135, 240, 102, 222, 57, 101, 250,
            192, 138, 17, 31, 243, 192, 141, 18, 66, 91, 112, 71, 42, 209
        ]
    );
    let mut expect = b"ABC".repeat(10).to_vec();
    expect.extend(b"A".repeat(16 - (expect.len() % 16)));
    assert_eq!(aes_decrypt(&output_encrypt, key, iv).unwrap(), expect);
}

/// aes_encrypt with A padding
pub fn aes_encrypt(
    data: &[u8],
    key: &[u8],
    iv: &[u8],
) -> Result<Vec<u8>, symmetriccipher::SymmetricCipherError> {
    let mut decryptor = aes::cbc_encryptor(
        aes::KeySize::KeySize128,
        key,
        iv,
        crypto::blockmodes::NoPadding,
    );
    let mut data = data.to_vec();
    data.extend(b"A".repeat(16 - (data.len() % 16)));
    let mut final_result = Vec::<u8>::new();
    let mut read_buffer = crypto::buffer::RefReadBuffer::new(&data);
    let mut buffer = [0; 4096];
    let mut write_buffer = crypto::buffer::RefWriteBuffer::new(&mut buffer);

    loop {
        let result = decryptor
            .encrypt(&mut read_buffer, &mut write_buffer, true)
            .unwrap();
        final_result.extend(
            write_buffer
                .take_read_buffer()
                .take_remaining()
                .iter()
                .map(|&i| i),
        );
        match result {
            BufferResult::BufferUnderflow => break,
            BufferResult::BufferOverflow => {}
        }
    }

    Ok(final_result)
}

#[allow(dead_code)]
fn reply_pkg(data: &[u8]) -> Vec<u8> {
    let iv = b"abcdefghijklmnop";
    let aes_key = b"abcdefghijklmnop";
    let hmac_key = b"";
    let counter = 1u32;
    let reply_type = 0u32;
    let raw_pkg = [
        &counter.to_be_bytes()[..],
        &(data.len() as u32 + 4).to_be_bytes()[..],
        &reply_type.to_be_bytes()[..],
        &data,
    ]
    .concat();
    let raw_pkg_encrypted = aes_encrypt(&raw_pkg.as_slice(), aes_key, iv).unwrap();
    let hash = hmac_hash(hmac_key, raw_pkg_encrypted.as_slice());
    let buf = [
        &(raw_pkg_encrypted.len() as u32 + 16).to_be_bytes()[..],
        raw_pkg_encrypted.as_slice(),
        &hash[..],
    ]
    .concat();
    return buf;
}
#[test]
fn test_reply_pkg() {
    let result = reply_pkg(b"ABC");
    let expect = [
        0, 0, 0, 32, 218, 50, 53, 247, 185, 189, 208, 157, 205, 96, 140, 30, 214, 72, 253, 213, 1,
        229, 205, 140, 39, 57, 163, 175, 72, 244, 5, 131, 124, 15, 32, 229,
    ];
    assert_eq!(result, expect);
}

fn rdtsc() -> u64 {
    unsafe { std::arch::x86_64::_rdtsc() }
}

/// A random number generator based off of xorshift64
pub struct Rng(u64);

impl Rng {
    pub fn new() -> Self {
        Rng(0x8644d6eb17b7ab1a ^ rdtsc())
    }
    #[inline]
    fn rand(&mut self) -> usize {
        let val = self.0;
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 17;
        self.0 ^= self.0 << 43;
        val as usize
    }
    pub(crate) fn rand_range(&mut self, min: u64, max: u64) -> usize {
        (self.0 % (max - min) + min) as usize
    }
    pub(crate) fn gen_bytes(&mut self, len: usize) -> Vec<u8> {
        let mut res: Vec<u8> = vec![];
        for _ in 0..len {
            res.push(self.rand() as u8);
        }
        res
    }
}
