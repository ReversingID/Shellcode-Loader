# Shellcode Loader

Abusing callback to run shellcode.

### Overview

Eksekusi shellcode dengan `EnumerateLoadedModules`.

```c++
BOOL IMAGEAPI EnumerateLoadedModules (HANDLE hProcess, PENUMLOADED_MODULES_CALLBACK EnumLoadedModulesCallback, PVOID UserContext);
```

### Reference 

- [MSDN EnumerateLoadedModules](https://docs.microsoft.com/en-us/windows/win32/api/dbghelp/nf-dbghelp-enumerateloadedmodules)