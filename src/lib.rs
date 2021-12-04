#![feature(link_llvm_intrinsics)]
#![feature(asm)]

use detour::static_detour;
use ntapi::ntpsapi::{ThreadHideFromDebugger, THREADINFOCLASS};
use std::ffi::{c_void, CString};
use std::os::raw::c_long;
use std::time::Duration;
use std::{mem, thread};
use winapi::shared::minwindef::ULONG;
use winapi::um::debugapi::IsDebuggerPresent;
use winapi::um::libloaderapi::{GetModuleHandleA, GetProcAddress};
use winapi::um::winnt::{HANDLE, PVOID};
use winapi::{
    shared::minwindef::{self, BOOL, DWORD, HINSTANCE, LPVOID},
    um::consoleapi,
};

/// Link with llvm intrinsics
extern "C" {
    #[link_name = "llvm.returnaddress"]
    /// https://stackoverflow.com/questions/54999851/how-do-i-get-the-return-address-of-a-function
    fn return_address(level: i32) -> *const u8;
}

static_detour! {
    static NtSetInformationThreadFnHook: unsafe extern "system" fn (HANDLE, THREADINFOCLASS, PVOID, ULONG) -> NTSTATUS;
}

type NTSTATUS = c_long;
type NtSetInformationThreadFn =
    unsafe extern "system" fn(HANDLE, THREADINFOCLASS, PVOID, ULONG) -> NTSTATUS;

#[dllmain_rs::entry()]
fn real_entry() {
    unsafe {
        consoleapi::AllocConsole();
    }

    thread::spawn(|| {
        hook_NtSetInformationThread();
        loop {
            thread::sleep(Duration::from_secs(1));
        }
    });
}

fn log_NtSetInformationThread(
    thread_handle: HANDLE,
    thread_info_class: THREADINFOCLASS,
    thread_info: PVOID,
    thread_info_length: ULONG,
) -> NTSTATUS {
    let calling_ret_addr = unsafe { return_address(0) };
    let caller_addr = unsafe { return_address(1) };

    println!(
        "[+] NtSetInformationThread({:?}, {:?}, {:?}, {:?})\n[+] Calling Return Address: {:?}\n[+] Caller Address: {:?}",
        thread_handle, thread_info_class, thread_info, thread_info_length,
        calling_ret_addr,
        caller_addr
    );

    // just dont call the function if thread_info_class is ThreadHideFromDebugger
    // can also try to check for current module address
    // and if it is not called from the current module address range
    // then don't do anything
    // if thread_info_class == ThreadHideFromDebugger {
    //     println!("[+] ThreadHideFromDebugger detected! Undoing flag!");
    //     0
    // } else {
    //     unsafe {
    //         NtSetInformationThreadFnHook.call(
    //             thread_handle,
    //             thread_info_class,
    //             thread_info,
    //             thread_info_length,
    //         )
    //     }
    // }

    unsafe {
        NtSetInformationThreadFnHook.call(
            thread_handle,
            thread_info_class,
            thread_info,
            thread_info_length,
        )
    }
}

fn hook_NtSetInformationThread() {
    let addr = get_addr_exported_fn::<_, c_void>("ntdll.dll", "NtSetInformationThread");
    if !addr.is_null() {
        let addr = unsafe { mem::transmute::<_, NtSetInformationThreadFn>(addr) };

        unsafe {
            NtSetInformationThreadFnHook
                .initialize(addr, log_NtSetInformationThread)
                .unwrap()
                .enable()
                .unwrap();
        }
    } else {
        println!("[-] address is null!");
    }
}

fn get_addr_exported_fn<S: AsRef<str>, T>(module: S, symbol: S) -> *const T {
    unsafe {
        let module = module.as_ref();
        let symbol = symbol.as_ref();
        let name = CString::new(module).unwrap();
        let handle = GetModuleHandleA(name.as_ptr());
        let symbol_name = CString::new(symbol).unwrap();
        GetProcAddress(handle, symbol_name.as_ptr()) as *const T
    }
}
