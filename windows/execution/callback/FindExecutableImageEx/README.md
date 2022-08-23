# Shellcode Loader

Abusing callback to run shellcode.

### Overview

Eksekusi shellcode dengan `FindExecutableImageEx`.

```c++
HANDLE FindExecutableImageEx (PCSTR FileName, PCSTR SymbolPath, PSTR ImageFilePath, PFIND_EXE_FILE_CALLBACK Callback, PVOID CallerData);
```

### Reference 

- [MSDN FindExecutableImageEx](https://docs.microsoft.com/en-us/windows/win32/api/dbghelp/nf-dbghelp-findexecutableimageex)