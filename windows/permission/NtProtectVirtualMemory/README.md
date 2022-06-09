# Shellcode Loader

Change the memory protection of virtual address space.

### Overview

Ubah permission dengan `NtProtectVirtualMemory`.

```c++
NTSTATUS NtProtectVirtualMemory (HANDLE ProcessHandle, PVOID * BaseAddress, PULONG NumberOfBytesToProtect, ULONG NewAccessProtection, PULONG OldAccessProtection);
```

### Reference 

- [NTInternals NtProtectVirtualMemory](http://undocumented.ntinternals.net/UserMode/Undocumented%20Functions/Memory%20Management/Virtual%20Memory/NtProtectVirtualMemory.html)
