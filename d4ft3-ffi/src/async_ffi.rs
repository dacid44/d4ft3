use std::cell::RefCell;
use std::collections::HashMap;
use std::sync::{mpsc, Mutex, MutexGuard};
use d4ft3::{Connection, D4FTError, D4FTResult, TransferMode, UnencryptedSocket};
use libc::c_char;
use std::ffi::{CStr, CString};
use std::sync::mpsc::Sender;
use std::thread;
use cancellable_io::Canceller;
use lazy_static::lazy_static;
use crate::D4ftFfiResult;

lazy_static! {
    static ref CURRENT_TASK: Mutex<TaskState> = Mutex::new(TaskState::None);
}

enum TaskState {
    None,
    Cancelled,
    Running(Option<Canceller>),
    Finished(D4FTResult<String>),
}

fn finish_task(task: &mut TaskState, result: D4FTResult<String>) {
    *task = match task {
        TaskState::Running(_) => TaskState::Finished(result),
        TaskState::Cancelled => TaskState::None,
        _ => panic!("Unexpected other task running"),
    }
}

fn listen_thread(port: u16, addr: &str, send: Option<String>, tx: Sender<Canceller>) {
    let result = UnencryptedSocket::listen((addr, port), TransferMode::ReceiveText, Some(tx))
        .and_then(|conn| if let Some(text) = send {
            conn.send_text(&text, 3).map(|_| String::new())
        } else {
            conn.receive_text()
        });
    // Should not panic
    let mut task = CURRENT_TASK.lock().unwrap();
    finish_task(&mut *task, result);
}

fn connect_thread(port: u16, addr: &str, send: Option<String>) {
    let result = UnencryptedSocket::connect((addr, port), TransferMode::ReceiveText)
        .and_then(|conn| if let Some(text) = send {
            conn.send_text(&text, 3).map(|_| String::new())
        } else {
            conn.receive_text()
        });

    // Should not panic
    let mut task = CURRENT_TASK.lock().unwrap();
    finish_task(&mut *task, result);
}

#[no_mangle]
pub extern "C" fn send_text_async(s: *const c_char, a: *const c_char, port: u16, connect: bool) -> *mut c_char {
    // Should not panic
    let mut task = CURRENT_TASK.lock().unwrap();
    if !matches!(&*task, TaskState::None | TaskState::Finished(_)) {
        return CString::new("task already running").unwrap().into_raw();
    }
    let (input, addr) = unsafe {
        if s.is_null() || a.is_null() {
            return CString::new("null pointer").unwrap().into_raw();
        }
        (CStr::from_ptr(s), CStr::from_ptr(a))
    };

    let input = input.to_str().unwrap();
    let addr = addr.to_str().unwrap();

    *task = TaskState::Running(if connect {
        thread::spawn(move || connect_thread(port, addr, Some(input.to_string())));
        None
    } else {
        let (tx, rx) = mpsc::channel::<Canceller>();
        thread::spawn(move || listen_thread(port, addr, Some(input.to_string()), tx));
        Some(rx.recv().expect("Listener function hung up unexpectedly"))
    });

    CString::new("started task").unwrap().into_raw()
}

#[no_mangle]
pub extern "C" fn receive_text_async(a: *const c_char, port: u16, connect: bool) -> *mut c_char {
    // Should not panic
    let mut task = CURRENT_TASK.lock().unwrap();
    if !matches!(&*task, TaskState::None | TaskState::Finished(_)) {
        return CString::new("task already running").unwrap().into_raw();
    }
    let addr = unsafe {
        if a.is_null() {
            return CString::new("null pointer").unwrap().into_raw();
        }
        CStr::from_ptr(a)
    };

    let addr = addr.to_str().unwrap();

    *task = TaskState::Running(if connect {
        thread::spawn(move || connect_thread(port, addr, None));
        None
    } else {
        let (tx, rx) = mpsc::channel::<Canceller>();
        thread::spawn(move || listen_thread(port, addr, None, tx));
        Some(rx.recv().expect("Listener function hung up unexpectedly"))
    });

    CString::new("started task").unwrap().into_raw()
}

#[no_mangle]
pub extern "C" fn cancel_task() -> *mut c_char {
    // Should not panic
    let mut task = CURRENT_TASK.lock().unwrap();
    if let TaskState::Running(Some(c)) = &*task {
        c.cancel(); // TODO: Not sure what to do with this result
        *task = TaskState::Cancelled;
        CString::new("cancelled task").unwrap().into_raw()
    } else {
        CString::new("no running cancellable task").unwrap().into_raw()
    }
}

#[no_mangle]
pub extern "C" fn get_result() -> D4ftFfiResult {
    // Should not panic
    let mut task = CURRENT_TASK.lock().unwrap();
    match &*task {
        TaskState::Running(_) => D4ftFfiResult::failure(""),
        TaskState::Finished(result) => {
            let ret = match result {
                Ok(val) => D4ftFfiResult::success(&val),
                Err(err) => D4ftFfiResult::failure(&format!("{:?}", err)),
            };
            *task = TaskState::None;
            ret
        }
        TaskState::Cancelled =>
            D4ftFfiResult::failure("task was cancelled"),
        TaskState::None =>
            D4ftFfiResult::failure("no running task"),
    }
}