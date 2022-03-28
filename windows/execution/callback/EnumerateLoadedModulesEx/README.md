# Shellcode Loader

Abusing callback to run shellcode.

### Overview

Eksekusi shellcode dengan `EnumerateLoadedModulesEx`.

```c++
BOOL IMAGEAPI EnumerateLoadedModulesEx( HANDLE hProcess, PENUMLOADED_MODULES_CALLBACK64 EnumLoadedModulesCallback, PVOIDUserContext);

BOOL IMAGEAPI EnumerateLoadedModulesExW( HANDLEhProcess, PENUMLOADED_MODULES_CALLBACKW64 EnumLoadedModulesCallback, PVOID UserContext);

BOOL IMAGEAPI EnumerateLoadedModules64( HANDLE hProcess, PENUMLOADED_MODULES_CALLBACK64 EnumLoadedModulesCallback, PVOIDUserContext);

BOOL IMAGEAPI EnumerateLoadedModulesW64( HANDLEhProcess, PENUMLOADED_MODULES_CALLBACKW64 EnumLoadedModulesCallback, PVOID UserContext);
```

### Reference 

- [MSDN EnumerateLoadedModulesEx](https://docs.microsoft.com/en-us/windows/win32/api/dbghelp/nf-dbghelp-enumerateloadedmodulesex)
- [MSDN EnumerateLoadedModulesExW](https://docs.microsoft.com/en-us/windows/win32/api/dbghelp/nf-dbghelp-enumerateloadedmodulesexw)
- [MSDN EnumerateLoadedModules64](https://docs.microsoft.com/en-us/windows/win32/api/dbghelp/nf-dbghelp-enumerateloadedmodules64)
- [MSDN EnumerateLoadedModulesW64](https://docs.microsoft.com/en-us/windows/win32/api/dbghelp/nf-dbghelp-enumerateloadedmodulesw64)