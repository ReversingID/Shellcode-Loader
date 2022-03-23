# Shellcode Loader

Allocate memory for executing shellcode later.

### Overview

Alokasi dengan `VirtualAlloc2` dan dealokasi dengan `VirtualFree`.

```c++
LPVOID VirtualAlloc2(HANDLE Process, PVOID BaseAddress, SIZE_T Size, ULONG AllocationType, ULONG PageProtection, MEM_EXTENDED_PARAMETER ExtendedParameters, ULONG ParameterCount);

BOOL VirtualProtect (LPVOID lpAddress, SIZE_T dwSize, DWORD  flNewProtect, PDWORD lpflOldProtect);

BOOL VirtualFree(LPVOID lpAddress, SIZE_T dwSize, DWORD dwFreeType);
```

### Reference 

- [MSDN VirtualAlloc2](https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualalloc2)
- [MSDN VirtualProtect](https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotect)
- [MSDN VirtualFree](https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualfree)
