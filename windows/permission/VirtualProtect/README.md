# Shellcode Loader

Change the memory protection of virtual address space.

### Overview

Ubah permission dengan `VirtualProtect`.

```c++
BOOL VirtualProtect (LPVOID lpAddress, SIZE_T dwSize, DWORD  flNewProtect, PDWORD lpflOldProtect);
```

### Reference 

- [MSDN VirtualProtect](https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotect)
