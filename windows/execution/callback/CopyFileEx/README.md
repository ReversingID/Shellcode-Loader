# Shellcode Loader

Abusing callback to run shellcode.

### Overview

Eksekusi shellcode dengan `CopyFileEx`.

```c++
BOOL CopyFileExA (LPCSTR lpExistingFileName, LPCSTR lpNewFileName, LPPROGRESS_ROUTINE lpProgressRoutine, LPVOID lpData, LPBOOL pbCancel, DWORD dwCopyFlags);

BOOL CopyFileExW (LPCWSTR lpExistingFileName, LPCWSTR lpNewFileName, LPPROGRESS_ROUTINE lpProgressRoutine, LPVOID lpData, LPBOOL pbCancel, DWORD dwCopyFlags);
```

### Reference 

- [MSDN CopyFileExA](https://docs.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-copyfileexa)
- [MSDN CopyFileExW](https://docs.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-copyfileexw)