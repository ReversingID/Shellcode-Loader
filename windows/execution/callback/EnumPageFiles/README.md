# Shellcode Loader

Abusing callback to run shellcode.

### Overview

Eksekusi shellcode dengan `EnumPageFiles`.

```c++
BOOL EnumPageFilesA (PENUM_PAGE_FILE_CALLBACKA pCallBackRoutine, LPVOID pContext);

BOOL EnumPageFilesW (PENUM_PAGE_FILE_CALLBACKW pCallBackRoutine, LPVOID pContext);
```

### Reference 

- [MSDN EnumPageFilesA](https://docs.microsoft.com/en-us/windows/win32/api/psapi/nf-psapi-enumpagefilesa)
- [MSDN EnumPageFilesW](https://docs.microsoft.com/en-us/windows/win32/api/psapi/nf-psapi-enumpagefilesw)