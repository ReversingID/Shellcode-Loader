# Shellcode Loader

Abusing callback to run shellcode.

### Overview

Eksekusi shellcode dengan `EnumResourceTypes`.

Enumerasi resource types di dalam module dan eksekusi callback untuk memproses tiap resource type yang diidentifikasi.

```c++
BOOL EnumResourceTypesA (HMODULE hModule, ENUMRESTYPEPROCA lpEnumFunc, LONG_PTR lParam);

BOOL EnumResourceTypesW (HMODULE hModule, ENUMRESTYPEPROCW lpEnumFunc, LONG_PTR lParam);
```

### Reference 

- [MSDN EnumResourceTypesA](https://docs.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-enumresourcetypesa)
- [MSDN EnumResourceTypesW](https://docs.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-enumresourcetypesw)