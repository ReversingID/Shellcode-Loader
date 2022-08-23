# Shellcode Loader

Abusing callback to run shellcode.

### Overview

Eksekusi shellcode dengan `FindDebugInfoFileEx`.

```c++
HANDLE FindDebugInfoFileEx (PCSTR FileName, PCSTR SymbolPath, PSTR DebugFilePath, PFIND_DEBUG_FILE_CALLBACK Callback, PVOID CallerData);
```

### Reference 

- [MSDN FindDebugInfoFileEx](https://docs.microsoft.com/en-us/windows/win32/api/dbghelp/nf-dbghelp-finddebuginfofileex)