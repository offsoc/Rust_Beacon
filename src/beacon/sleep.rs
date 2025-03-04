use crate::util::data_parse::{beacon_read_i32, beacon_send_result};
use crate::util::jobs::CALLBACK_OUTPUT;
use crate::BEACON;
use lazy_static::lazy_static;
use rand::Rng;
use std::io::Cursor;

use std::sync::Mutex;

lazy_static! {
    static ref GLOBAL_VAR_SLEEP: Mutex<i32> = Mutex::new(3000); // 定义全局变量
    static ref GLOBAL_VAR_JITTER: Mutex<i32> = Mutex::new(0); // 定义全局变量
}

// 定义 beacon_sleep 函数
pub fn beacon_sleep(mut decrypted_cursor: Cursor<Vec<u8>>) {
    // 读取命令长度
    let cmd_len_result = beacon_read_i32(&mut decrypted_cursor);
    let cmd_len = match cmd_len_result {
        Ok(len) => len,
        Err(e) => {
            eprintln!("Failed to read command length: {}", e);
            return;
        }
    };

    // 解析Sleep
    let sleep_value = beacon_read_i32(&mut decrypted_cursor);
    // 仅在 debug 模式下打印
    if cfg!(debug_assertions) {
        println!("CMD_TYPE_SLEEP: Sleep Length: {}", cmd_len);
    }

    let sleep_units = match sleep_value {
        Ok(len) => len,
        Err(e) => {
            eprintln!("Failed to read command length: {}", e);
            return;
        }
    };
    let sleep_ms = sleep_units; // 直接使用该值，因为单位已经是毫秒

    // 仅在 debug 模式下打印
    if cfg!(debug_assertions) {
        // 打印 sleep 值的十六进制和十进制
        println!("CMD_TYPE_SLEEP: sleep: 0x{:X} ({} ms)", sleep_ms, sleep_ms);
    }

    // 解析jitter
    let jitter_value = beacon_read_i32(&mut decrypted_cursor);
    // 仅在 debug 模式下打印
    if cfg!(debug_assertions) {
        println!("CMD_TYPE_SLEEP: Jitter Length: {}", cmd_len);
    }

    let jitter_units = match jitter_value {
        Ok(len) => len,
        Err(e) => {
            eprintln!("Failed to read command length: {}", e);
            return;
        }
    };
    // let jitter_ms = jitter_units; // 直接使用该值，因为单位已经是毫秒

    // 设置
    set_global_var(sleep_units, jitter_units);

    // 发送结果
    unsafe {
        if let Err(e) = beacon_send_result(b"sleep ok", &BEACON, CALLBACK_OUTPUT) {
            eprintln!("Failed to send result: {}", e);
        }
    }
}

// sleep 函数
pub fn beacon_sleep_run() -> u64 {
    let (sleep, jitter) = get_global_var();
    let random_sleep = generate_random_sleep(sleep, jitter);
    // println!("Random sleep value: {} ms", random_sleep);

    let sleep = milliseconds_to_seconds(random_sleep.try_into().unwrap());

    // 仅在 debug 模式下打印
    if cfg!(debug_assertions) {
        println!("CMD_TYPE_SLEEP: sleep:  ({} s)", sleep);
    }

    sleep as u64
}

// 毫秒转换秒
pub fn milliseconds_to_seconds(milliseconds: u64) -> f64 {
    milliseconds as f64 / 1000.0
}

// 计算随机范围
pub fn generate_random_sleep(sleep: i32, jitter_percentage: i32) -> i32 {
    // 确保 jitter_percentage 是非负的
    let jitter = if jitter_percentage < 0 {
        0
    } else {
        (sleep.abs() as u32 * jitter_percentage.abs() as u32) / 100
    };

    // 计算 sleep 的上下波动范围
    let min_sleep = sleep - jitter.try_into().unwrap_or(0); // 将 jitter 转换为 i32
    let max_sleep = sleep + jitter.try_into().unwrap_or(0); // 将 jitter 转换为 i32

    // 生成随机数
    let mut rng = rand::thread_rng();
    let random_sleep = rng.gen_range(min_sleep..=max_sleep); // 包含边界

    // 返回随机睡眠值，确保其不小于 0
    random_sleep.max(0)
}

// 设置值
pub fn set_global_var(value_sleep: i32, value_jitter: i32) {
    let mut num1 = GLOBAL_VAR_SLEEP.lock().unwrap(); // 获取锁
    let mut num2 = GLOBAL_VAR_JITTER.lock().unwrap(); // 获取锁
    *num1 = value_sleep; // 修改值
    *num2 = value_jitter; // 修改值
}

// 获取值
pub fn get_global_var() -> (i32, i32) {
    let num1 = GLOBAL_VAR_SLEEP.lock().unwrap(); // 获取锁
    let num2 = GLOBAL_VAR_JITTER.lock().unwrap(); // 获取锁
    (*num1, *num2) // 返回值
}
