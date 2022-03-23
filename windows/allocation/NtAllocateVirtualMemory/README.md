# Shellcode Loader

Allocate memory for executing shellcode later.

### Overview

Alokasi dengan `NtAllocateVirtualMemory` dan dealokasi dengan `NtFreeVirtualMemory`.

```c++
NTSTATUS NtAllocateVirtualMemory (HANDLE ProcessHandle, PVOID BaseAddress, ULONG ZeroBits, PULONG RegionSize, ULONG AllocationType, ULONG Protect);

NTSTATUS NtProtectVirtualMemory (HANDLE ProcessHandle, PVOID * BaseAddress, PULONG NumberOfBytesToProtect, ULONG NewAccessProtection, PULONG OldAccessProtection);

NTSTATUS NtFreeVirtualMemory (HANDLE ProcessHandle, PVOID * BaseAddress, PULONG RegionSize, ULONG FreeType);
```

### Reference 

- [NTInternals NtAllocateVirtualMemory](http://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FMemory%20Management%2FVirtual%20Memory%2FNtAllocateVirtualMemory.html)
- [NTInternals NtFreeVirtualMemory](http://undocumented.ntinternals.net/UserMode/Undocumented%20Functions/Memory%20Management/Virtual%20Memory/NtProtectVirtualMemory.html)
- [NTInternals NtFreeVirtualMemory](http://undocumented.ntinternals.net/UserMode/Undocumented%20Functions/Memory%20Management/Virtual%20Memory/NtFreeVirtualMemory.html)
