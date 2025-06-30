#![feature(asm)]

use std::ffi::c_void;
use std::ptr::null_mut;

#[repr(C)]
pub struct CLIENT_ID {
    UniqueProcess: *mut c_void,
    UniqueThread: *mut c_void,
}

#[repr(C)]
pub struct OBJECT_ATTRIBUTES {
    Length: u32,
    RootDirectory: *mut c_void,
    ObjectName: *mut c_void,
    Attributes: u32,
    SecurityDescriptor: *mut c_void,
    SecurityQualityOfService: *mut c_void,
}

#[allow(non_snake_case)]
unsafe fn NtWriteVirtualMemory(
    process_handle: usize,
    base_address: *mut c_void,
    buffer: *const c_void,
    size: usize,
    bytes_written: *mut usize,
) -> u32 {
    let syscall_number: u32 = 0x003A; // Change this for your OS version
    let ret: u32;

    asm!(
    "mov r10, rcx",        // syscall ABI requirement (r10 ← rcx)
    "mov eax, {0}",        // syscall number in eax
    "syscall",             // syscall instruction
    in(reg) syscall_number,
    in("rcx") process_handle,
    in("rdx") base_address,
    in("r8") buffer,
    in("r9") size,
    in("r11") bytes_written,
    out("rax") ret,        // syscall return value
    out("rcx") _, out("rdx") _, out("r8") _, out("r9") _, out("r10") _, out("r11") _,
    options(nostack)
    );

    ret
}
