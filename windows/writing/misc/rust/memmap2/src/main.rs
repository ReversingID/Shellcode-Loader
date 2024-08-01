/*
    Shellcode Loader
    Archive of Reversing.ID

    Allocation and change permission with memmap2.
    memmap2 is a wrapper to memory operations (not only in windows).

Compile:
    $ cargo build

Technique:
    - allocation:   VirtualAlloc
    - writing:      
    - permission:   
    - execution:    unsafe call to function pointer
*/

use memmap2::MmapOptions;
use std::mem::transmute;

fn main() {
    // shellcode storage in stack
    let payload: [u8; 4] = [0x90, 0x90, 0xCC, 0xC3];

    // allocate memory buffer for payload as READ-WRITE (no executable)
    let mut mmap = MmapOptions::new()
        .len(payload.len())
        .map_anon()
        .expect("[-] unable to allocate");

    // copy payload to the buffer
    mmap.copy_from_slice(&payload);

    // make buffer executable (R-X)
    let mmap = mmap
        .make_exec()
        .expect("[-] unable to change permission");

    // cast the payload into function and execute
    unsafe {
        let ep: extern "C" fn() = transmute(mmap.as_ptr());
        ep();
    }
}
