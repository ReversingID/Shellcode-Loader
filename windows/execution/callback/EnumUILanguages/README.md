# Shellcode Loader

Abusing callback to run shellcode.

### Overview

Eksekusi shellcode dengan `EnumUILanguages`.

```c++
BOOL EnumUILanguagesA (UILANGUAGE_ENUMPROCA lpUILanguageEnumProc, DWORD dwFlags, LONG_PTR lParam);

BOOL EnumUILanguagesW (UILANGUAGE_ENUMPROCW lpUILanguageEnumProc, DWORD dwFlags, LONG_PTR lParam);
```

### Reference 

- [MSDN EnumUILanguagesA](https://docs.microsoft.com/en-us/windows/win32/api/winnls/nf-winnls-enumuilanguagesa)
- [MSDN EnumUILanguagesW](https://docs.microsoft.com/en-us/windows/win32/api/winnls/nf-winnls-enumuilanguagesw)