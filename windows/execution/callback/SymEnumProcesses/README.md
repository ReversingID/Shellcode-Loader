# Shellcode Loader

Abusing callback to run shellcode.

### Overview

Eksekusi shellcode dengan `SymEnumProcesses`.

```c++
BOOL IMAGEAPI SymEnumProcesses (PSYM_ENUMPROCESSES_CALLBACK EnumProcessesCallback, PVOID UserContext);

BOOL IMAGEAPI SymInitialize (HANDLE hProcess, PCSTR UserSearchPath, BOOL fInvadeProcess);
```

### Reference 

- [MSDN SymEnumProcesses](https://docs.microsoft.com/en-us/windows/win32/api/dbghelp/nf-dbghelp-symenumprocesses)
- [MSDN SymInitialize](https://docs.microsoft.com/en-us/windows/win32/api/dbghelp/nf-dbghelp-syminitialize)