# Shellcode Loader

Abusing callback to run shellcode.

### Overview

Eksekusi shellcode dengan `EnumTimeFormatsEx`.

```c++
BOOL EnumTimeFormatsEx (TIMEFMT_ENUMPROCEX lpTimeFmtEnumProcEx, LPCWSTR lpLocaleName, DWORD dwFlags, LPARAM lParam);
```

### Reference 

- [MSDN EnumTimeFormatsEx](https://docs.microsoft.com/en-us/windows/win32/api/winnls/nf-winnls-enumtimeformatsex)