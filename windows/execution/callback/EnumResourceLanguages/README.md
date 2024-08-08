# Shellcode Loader

Abusing callback to run shellcode.

### Overview

Eksekusi shellcode dengan `EnumResourceLanguages`.

```c++
BOOL EnumResourceLanguagesA(HMODULE hModule, LPCSTR lpType, LPCSTR lpName, ENUMRESLANGPROCA lpEnumFunc, LONG_PTR lParam);

BOOL EnumResourceLanguagesW(HMODULE hModule, LPCWSTR lpType, LPCWSTR lpName, ENUMRESLANGPROCW lpEnumFunc, LONG_PTR lParam);
```

### Reference 

- [MSDN EnumResourceLanguagesA](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-enumresourcelanguagesa)
- [MSDN EnumResourceLanguagesW](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-enumresourcelanguagesw)