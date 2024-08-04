/*
    Shellcode Loader
    Archive of Reversing.ID

    Executing shellcode by jump to it.
    Write inline assembly to jump to shellcode directly.

Compile:
    $ cargo build

Technique:
    - allocation:   VirtualAlloc
    - writing:      copy()
    - permission:   VirtualProtect
    - execution:    jmp to payload
*/

use std::{arch::asm, ptr};
use winapi::um::{
    memoryapi::{VirtualAlloc, VirtualFree, VirtualProtect},
    winnt::{
        MEM_COMMIT, MEM_RELEASE, MEM_RESERVE, 
        PAGE_READWRITE, PAGE_EXECUTE_READ
    },
};

fn main() {
    // shellcode storage in stack
    let payload: [u8; 4] = [0x90, 0x90, 0xCC, 0xC3];
    let mut old_protect = PAGE_READWRITE;
    
    unsafe {
        // allocate memory buffer for payload as READ-WRITE (no executable)
        let runtime = VirtualAlloc(
            ptr::null_mut(),
            payload.len(),
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE
        );

        if runtime.is_null() {
            println!("[-] unable to allocate");
            return;
        }

        // copy payload to the buffer
        ptr::copy(payload.as_ptr(), runtime.cast(), payload.len());

        // make buffer executable (R-X)
        let retval = VirtualProtect (
            runtime,
            payload.len(),
            PAGE_EXECUTE_READ,
            &mut old_protect
        );

        if retval != 0 {
            // inline assembly to jump to shellcode (64-bit register)
            asm!("lea rax, [{}]", in(reg) runtime);
            asm!("jmp rax");

            // // use this to call function directly
            // asm!("call {}", in(reg) runtime);
        }

        VirtualFree(runtime, payload.len(), MEM_RELEASE);
    }
}
