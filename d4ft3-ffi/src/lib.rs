mod async_ffi;

use d4ft3::{Connection, D4FTError, TransferMode, UnencryptedSocket};
use libc::c_char;
use std::ffi::{CStr, CString};

#[no_mangle]
pub extern "C" fn send_text(s: *const c_char, a: *const c_char, port: u16, connect: bool) -> *mut c_char {
    let (input, addr) = unsafe {
        if s.is_null() || a.is_null() {
            return CString::new("null pointer").unwrap().into_raw();
        }
        (CStr::from_ptr(s), CStr::from_ptr(a))
    };

    let input = input.to_str().unwrap();
    let addr = addr.to_str().unwrap();
    let result = if connect {
        UnencryptedSocket::connect((addr, port), TransferMode::SendText)
    } else {
        UnencryptedSocket::listen((addr, port), TransferMode::SendText, None)
    }.and_then(|conn| conn.send_text(input, 3));

    CString::new(match result {
        Ok(_) => "success".to_string(),
        Err(err) => format!("{:?}", err),
    })
        .unwrap()
        .into_raw()
}

#[repr(C)]
pub struct D4ftFfiResult {
    value: *mut c_char,
    message: *mut c_char,
}

impl D4ftFfiResult {
    pub(crate) fn success(value: &str) -> Self {
        Self {
            value: CString::new(value).unwrap().into_raw(),
            message: CString::new("success").unwrap().into_raw(),
        }
    }

    pub (crate) fn failure(message: &str) -> Self {
        Self {
            value: CString::new("").unwrap().into_raw(),
            message: CString::new(message).unwrap().into_raw(),
        }
    }
}

#[no_mangle]
pub extern "C" fn receive_text(a: *const c_char, port: u16, connect: bool) -> D4ftFfiResult {
    let addr = unsafe {
        if a.is_null() {
            return D4ftFfiResult::failure("null pointer");
        }
        CStr::from_ptr(a)
    };

    let addr = addr.to_str().unwrap();
    let result = if connect {
        UnencryptedSocket::connect((addr, port), TransferMode::ReceiveText)
    } else {
        UnencryptedSocket::listen((addr, port), TransferMode::ReceiveText, None)
    }.and_then(|conn| conn.receive_text());

    match result {
        Ok(val) => D4ftFfiResult::success(&val),
        Err(err) => D4ftFfiResult::failure(&format!("{:?}", err)),
    }
}

#[no_mangle]
pub extern "C" fn free_string(s: *mut c_char) {
    unsafe {
        if s.is_null() {
            return;
        }
        drop(CString::from_raw(s));
    }
}
