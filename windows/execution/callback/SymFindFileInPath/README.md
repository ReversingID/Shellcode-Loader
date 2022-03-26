# Shellcode Loader

Abusing callback to run shellcode.

### Overview

Eksekusi shellcode dengan `SymFindFileInPath`.

```c++
BOOL IMAGEAPI SymFindFileInPath ( HANDLE hprocess, PCSTR SearchPath, PCSTR FileName, PVOID id, DWORD two, DWORD three, DWORD flags, PSTR FoundFile, PFINDFILEINPATHCALLBACK callback, PVOID context);

BOOL IMAGEAPI SymSrvGetFileIndexInfo (PCSTR File, PSYMSRV_INDEX_INFO Info, DWORD Flags);
```

### Reference 

- [MSDN SymFindFileInPath](https://docs.microsoft.com/en-us/windows/win32/api/dbghelp/nf-dbghelp-symfindfileinpath)
- [MSDN SymSrvGetFileIndexInfo](https://docs.microsoft.com/en-us/windows/win32/api/dbghelp/nf-dbghelp-symsrvgetfileindexinfo)