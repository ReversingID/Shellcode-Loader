# Shellcode Loader

Abusing callback to run shellcode.

### Overview

Eksekusi shellcode dengan `EnumResourceNamesEx`.

Enumerasi resource types di dalam module dan eksekusi callback untuk memproses tiap resource type yang diidentifikasi.

```c++
BOOL EnumResourceNamesExA (HMODULE hModule, LPCSTR lpType, ENUMRESNAMEPROCA lpEnumFunc, LONG_PTR lParam, DWORD dwFlags, LANGID LangId);

BOOL EnumResourceNamesExW (HMODULE hModule, LPCWSTR lpType, ENUMRESNAMEPROCW lpEnumFunc, LONG_PTR lParam, DWORD dwFlags, LANGID LangId);
```

### Reference 

- [MSDN EnumResourceNamesExA](https://docs.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-enumresourcenamesexa)
- [MSDN EnumResourceNamesExW](https://docs.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-enumresourcenamesexw)