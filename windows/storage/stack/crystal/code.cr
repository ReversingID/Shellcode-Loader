#   Shellcode Loader
#   Archive of Reversing.ID 
#
#   storing payload in stack 
#
# Run:
#   $ code.cr 
# 
# Technique:
#   - allocation:   VirtualAlloc
#   - writing:      memcpy
#   - permission:   VirtualProtect
#   - execution:    invoke directly

# define PAGE_EXECUTE_READ because it's not defined in lib
PAGE_EXECUTE_READ = 0x20 

# shellcode storage in stack
payload = IO::Memory.new Bytes[  0x90, 0x90, 0xCC, 0xC3 ]

# allocate memory buffer for payload as READ-WRITE (no executable)
runtime = LibC.VirtualAlloc(nil, payload.size, LibC::MEM_COMMIT | LibC::MEM_RESERVE, LibC::PAGE_READWRITE)

# copy payload to the buffer 
Intrinsics.memcpy(runtime, payload.buffer, payload.size, false)

# make buffer executable (R-X)
LibC.VirtualProtect(runtime, payload.size, PAGE_EXECUTE_READ, out _)

# execute the payload 
t = Proc(Int32).new(runtime, runtime)
t.call 