# Shellcode Loader

Allocate memory for executing shellcode later.

### Overview

Alokasi melalui memory mapping dengan `CreateFileMapping`.

```c++
HANDLE CreateFileMappingA (HANDLE hFile, LPSECURITY_ATTRIBUTES lpFileMappingAttributes, DWORD flProtect, DWORD dwMaximumSizeHigh, DWORD dwMaximumSizeLow, LPCSTR lpName);

HANDLE CreateFileMappingW (HANDLE hFile, LPSECURITY_ATTRIBUTES lpFileMappingAttributes, DWORD flProtect, DWORD dwMaximumSizeHigh, DWORD dwMaximumSizeLow, LPCWSTR lpName);

LPVOID MapViewOfFile (HANDLE hFileMappingObject, DWORD dwDesiredAccess, DWORD dwFileOffsetHigh, DWORD dwFileOffsetLow, SIZE_T dwNumberOfBytesToMap);

BOOL UnmapViewOfFile(LPCVOID lpBaseAddress);
```

### Reference 

- [MSDN CreateFileMappingA](https://docs.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createfilemappinga)
- [MSDN CreateFileMappingW](https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-createfilemappingw)
- [MSDN MapViewOfFile](https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-mapviewoffile)
- [MSDN UnmapViewOfFile](https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-unmapviewoffile)