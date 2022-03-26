# Shellcode Loader

Abusing callback to run shellcode.

### Overview

Eksekusi shellcode dengan `EnumResourceTypesEx`.

Enumerasi resource types di dalam module dan eksekusi callback untuk memproses tiap resource type yang diidentifikasi.

```c++
BOOL EnumResourceTypesExA (HMODULE hModule, ENUMRESTYPEPROCA lpEnumFunc, LONG_PTR lParam, DWORD dwFlags, LANGID LangId);

BOOL EnumResourceTypesExW (HMODULE hModule, ENUMRESTYPEPROCW lpEnumFunc, LONG_PTR lParam, DWORD dwFlags, LANGID LangId);
```

### Reference 

- [MSDN EnumResourceTypesExA](https://docs.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-enumresourcetypesa)
- [MSDN EnuMResourceTypesExW](https://docs.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-enumresourcetypesexw)