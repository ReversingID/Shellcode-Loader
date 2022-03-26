# Shellcode Loader

Abusing callback to run shellcode.

### Overview

Eksekusi shellcode dengan `EnumSystemLocales`.

```c++
BOOL EnumSystemLocalesA (LOCALE_ENUMPROCA lpLocaleEnumProc, DWORD dwFlags);

BOOL EnumSystemLocalesW (LOCALE_ENUMPROCW lpLocaleEnumProc, DWORD dwFlags);
```

### Reference 

- [MSDN EnumSystemLocalesA](https://docs.microsoft.com/en-us/windows/win32/api/winnls/nf-winnls-enumsystemlocalesa)
- [MSDN EnumSystemLocalesW](https://docs.microsoft.com/en-us/windows/win32/api/winnls/nf-winnls-enumsystemlocalesw)