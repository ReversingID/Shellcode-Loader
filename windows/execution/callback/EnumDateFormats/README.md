# Shellcode Loader

Abusing callback to run shellcode.

### Overview

Eksekusi shellcode dengan `EnumDateFormats`.

```c++
BOOL EnumDateFormatsA (DATEFMT_ENUMPROCA lpDateFmtEnumProc, LCID Locale, DWORD dwFlags);

BOOL EnumDateFormatsW (DATEFMT_ENUMPROCW lpDateFmtEnumProc, LCID Locale, DWORD dwFlags);
```

### Reference 

- [MSDN EnumDateFormatsA](https://docs.microsoft.com/en-us/windows/win32/api/winnls/nf-winnls-enumdateformatsa)
- [MSDN EnumDateFormatsW](https://docs.microsoft.com/en-us/windows/win32/api/winnls/nf-winnls-enumdateformatsw)