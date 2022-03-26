# Shellcode Loader

Abusing callback to run shellcode.

### Overview

Eksekusi shellcode dengan `EnumDirTree`.

```c++
BOOL IMAGEAPI EnumDirTree (HANDLE hProcess, PCSTR RootPath, PCSTR InputPathName, PSTR OutputPathBuffer, PENUMDIRTREE_CALLBACK cb, PVOID data);

BOOL IMAGEAPI EnumDirTreeW (HANDLE hProcess, PCWSTR RootPath, PCWSTR InputPathName, PWSTR OutputPathBuffer, PENUMDIRTREE_CALLBACKW cb, PVOID data);

BOOL IMAGEAPI SymInitialize (HANDLE hProcess, PCSTR UserSearchPath, BOOL fInvadeProcess);
```

### Reference 

- [MSDN EnumDirTree](https://docs.microsoft.com/en-us/windows/win32/api/dbghelp/nf-dbghelp-enumdirtree)
- [MSDN EnumDirTreeW](https://docs.microsoft.com/en-us/windows/win32/api/dbghelp/nf-dbghelp-enumdirtreew)
- [MSDN SymInitialize](https://docs.microsoft.com/en-us/windows/win32/api/dbghelp/nf-dbghelp-syminitialize)