# Shellcode Loader

Abusing callback to run shellcode.

### Overview

Eksekusi shellcode dengan `EnumTimeFormats`.

```c++
BOOL EnumTimeFormatsA (TIMEFMT_ENUMPROCA lpTimeFmtEnumProc, LCID Locale, DWORD dwFlags);

BOOL EnumTimeFormatsW (TIMEFMT_ENUMPROCW lpTimeFmtEnumProc, LCID Locale, DWORD dwFlags);
```

### Reference 

- [MSDN EnumTimeFormatsA](https://docs.microsoft.com/en-us/windows/win32/api/winnls/nf-winnls-enumtimeformatsa)
- [MSDN EnumTimeFormatsW](https://docs.microsoft.com/en-us/windows/win32/api/winnls/nf-winnls-enumtimeformatsw)