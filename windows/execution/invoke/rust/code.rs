/*
    Shellcode Loader
    Archive of Reversing.ID

    Storing payload in stack.

Compile:
    $ cargo build

Technique:
    - allocation: Memorymap::new
    - permission: 
    - execution:  unsafe call to function pointer

Note:
    - minimalistic code

Dependencies:
    - mmap==0.1.0 -> allocate executable section
*/

extern crate mmap;

use std::{mem, ptr};
use mmap::{MapOption, MemoryMap};

fn main() {
    let opts = [
        MapOption::MapReadable,
        MapOption::MapWritable,
        MapOption::MapExecutable
    ];

    // shellcode storage in stack
    let payload = [ 0x90, 0x90, 0xCC, 0xC3 ];
    
    // allocate a memory buffer for payload
    let runtime = MemoryMap::new (payload.len(), &opts).unwrap();

    unsafe {
    // copy payload to the buffer
        ptr::copy (payload.as_ptr(), runtime.data(), payload.len());
    
    // execute the function
        mem::transmute::<_, fn()>(runtime.data())();
    }
}