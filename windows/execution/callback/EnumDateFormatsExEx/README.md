# Shellcode Loader

Abusing callback to run shellcode.

### Overview

Eksekusi shellcode dengan `EnumDateFormatsExEx`.

```c++
BOOL EnumDateFormatsExEx (DATEFMT_ENUMPROCEXEX lpDateFmtEnumProcExEx, LPCWSTR lpLocaleName, DWORD dwFlags, LPARAM lParam);
```

### Reference 

- [MSDN EnumDateFormatsExEx](https://docs.microsoft.com/en-us/windows/win32/api/winnls/nf-winnls-enumdateformatsexex)