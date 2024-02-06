# Shellcode Loader

Abusing callback to run shellcode.

### Overview

Eksekusi shellcode dengan `EnumerateLoadedModulesEx`.

```c++
BOOL EnumerateLoadedModulesEx (HANDLE hProcess, PENUMLOADED_MODULES_CALLBACK64 EnumLoadedModulesCallback, PVOIDUserContext);

BOOL EnumerateLoadedModulesExW (HANDLEhProcess, PENUMLOADED_MODULES_CALLBACKW64 EnumLoadedModulesCallback, PVOID UserContext);

BOOL EnumerateLoadedModules64 (HANDLE hProcess, PENUMLOADED_MODULES_CALLBACK64 EnumLoadedModulesCallback, PVOIDUserContext);

BOOL EnumerateLoadedModulesW64 (HANDLEhProcess, PENUMLOADED_MODULES_CALLBACKW64 EnumLoadedModulesCallback, PVOID UserContext);
```

### Reference 

- [MSDN EnumerateLoadedModulesEx](https://docs.microsoft.com/en-us/windows/win32/api/dbghelp/nf-dbghelp-enumerateloadedmodulesex)
- [MSDN EnumerateLoadedModulesExW](https://docs.microsoft.com/en-us/windows/win32/api/dbghelp/nf-dbghelp-enumerateloadedmodulesexw)
- [MSDN EnumerateLoadedModules64](https://docs.microsoft.com/en-us/windows/win32/api/dbghelp/nf-dbghelp-enumerateloadedmodules64)
- [MSDN EnumerateLoadedModulesW64](https://docs.microsoft.com/en-us/windows/win32/api/dbghelp/nf-dbghelp-enumerateloadedmodulesw64)