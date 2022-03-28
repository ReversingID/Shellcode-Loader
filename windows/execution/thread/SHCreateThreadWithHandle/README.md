# Shellcode Loader

Abusing callback to run shellcode.

### Overview

Eksekusi shellcode dengan `SHCreateThreadWithHandle`.

```c++
BOOL SHCreateThreadWithHandle (LPTHREAD_START_ROUTINE pfnThreadProc, void * pData, SHCT_FLAGS flags, LPTHREAD_START_ROUTINE pfnCallback, HANDLE * pHandle);
```

### Reference 

- [MSDN SHCreateThreadWithHandle](https://docs.microsoft.com/en-us/windows/win32/api/shlwapi/nf-shlwapi-shcreatethreadwithhandle)