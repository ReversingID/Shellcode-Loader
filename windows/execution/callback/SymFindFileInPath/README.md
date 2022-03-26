# Shellcode Loader

Abusing callback to run shellcode.

### Overview

Eksekusi shellcode dengan `SymFindFileInPath`.

```c++
BOOL IMAGEAPI SymFindFileInPath(
  [in]           HANDLE                  hprocess,
  [in, optional] PCSTR                   SearchPath,
  [in]           PCSTR                   FileName,
  [in, optional] PVOID                   id,
  [in]           DWORD                   two,
  [in]           DWORD                   three,
  [in]           DWORD                   flags,
  [out]          PSTR                    FoundFile,
  [in, optional] PFINDFILEINPATHCALLBACK callback,
  [in, optional] PVOID                   context
);

BOOL IMAGEAPI SymSrvGetFileIndexInfo (PCSTR File, PSYMSRV_INDEX_INFO Info, DWORD Flags);
```

### Reference 

- [MSDN SymFindFileInPath](https://docs.microsoft.com/en-us/windows/win32/api/dbghelp/nf-dbghelp-symfindfileinpath)
- [MSDN SymSrvGetFileIndexInfo](https://docs.microsoft.com/en-us/windows/win32/api/dbghelp/nf-dbghelp-symsrvgetfileindexinfo)