# Shellcode Loader

Change the memory protection of virtual address space.

### Overview

Ubah permission dengan `VirtualProtectEx`.

```c++
BOOL VirtualProtectEx(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD  flNewProtect, PDWORD lpflOldProtect);
```

### Reference 

- [MSDN VirtualProtectEx](https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotectex)
