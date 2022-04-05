# Shellcode Loader

Writing shellcode to allocated memory.

### Overview

Penyalinan shellcode menggunakan `NtWriteVirtualMemory`.

```c++
NTSTATUS NtWriteVirtualMemory (HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, ULONG NumberOfBytesToWrite, PULONG NumberOfBytesWritten);
```

### Reference

- [NTInternals NtWriteVirtualMemory](http://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FMemory%20Management%2FVirtual%20Memory%2FNtWriteVirtualMemory.html)