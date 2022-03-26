# Shellcode Loader

Abusing callback to run shellcode.

### Overview

Eksekusi shellcode dengan `EnumResourceTypes`.

Enumerasi resource types di dalam module dan eksekusi callback untuk memproses tiap resource type yang diidentifikasi.

```c++
BOOL EnumResourceTypesA (HMODULE hModule, ENUMRESTYPEPROCA lpEnumFunc, LONG_PTR lParam);
```

### Reference 

- [MSDN EnumResourceTypes](https://docs.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-enumresourcetypesa)