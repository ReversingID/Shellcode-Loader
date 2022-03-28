# Shellcode Loader

Abusing callback to run shellcode.

### Overview

Eksekusi shellcode dengan `SHCreateThread`.

```c++
BOOL SHCreateThread (LPTHREAD_START_ROUTINE pfnThreadProc, void * pData, SHCT_FLAGS flags, LPTHREAD_START_ROUTINE pfnCallback);
```

### Reference 

- [MSDN SHCreateThread](https://docs.microsoft.com/en-us/windows/win32/api/shlwapi/nf-shlwapi-shcreatethread)