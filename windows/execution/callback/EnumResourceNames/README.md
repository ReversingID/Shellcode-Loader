# Shellcode Loader

Abusing callback to run shellcode.

### Overview

Eksekusi shellcode dengan `EnumResourceNames`.

Enumerasi resource types di dalam module dan eksekusi callback untuk memproses tiap resource type yang diidentifikasi.

```c++
BOOL EnumResourceNamesA (HMODULE hModule, LPCSTR lpType, ENUMRESNAMEPROCA lpEnumFunc, LONG_PTR lParam);

BOOL EnumResourceNamesW (HMODULE hModule, LPCWSTR lpType, ENUMRESNAMEPROCW lpEnumFunc, LONG_PTR lParam);
```

### Reference 

- [MSDN EnumResourceNamesA](https://docs.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-enumresourcenamesa)
- [MSDN EnumResourceNamesW](https://docs.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-enumresourcenamesw)