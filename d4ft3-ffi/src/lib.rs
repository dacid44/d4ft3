use d4ft3::{Connection, D4FTError, TransferMode, UnencryptedSocket};
use libc::c_char;
use std::ffi::{CStr, CString};

#[no_mangle]
pub extern "C" fn send_text(s: *const c_char, a: *const c_char, port: u16) -> *mut c_char {
    let (input, addr) = unsafe {
        if s.is_null() {
            return CString::new("null pointer").unwrap().into_raw();
        }
        (CStr::from_ptr(s), CStr::from_ptr(a))
    };

    let input = input.to_str().unwrap();
    let addr = addr.to_str().unwrap();
    let result = UnencryptedSocket::connect(
        (addr, port),
        TransferMode::SendText,
    )
        .and_then(|conn| conn.send_text(input, 3));

    CString::new(match result {
        Ok(_) => "success".to_string(),
        Err(err) => format!("{:?}", err),
    })
        .unwrap()
        .into_raw()
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
