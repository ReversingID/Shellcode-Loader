# Shellcode Loader

Abusing callback to run shellcode.

### Overview

Eksekusi shellcode dengan `EnumDateFormatsEx`.

```c++
BOOL EnumDateFormatsExA (DATEFMT_ENUMPROCEXA lpDateFmtEnumProcEx, LCID Locale, DWORD dwFlags);

BOOL EnumDateFormatsExW (DATEFMT_ENUMPROCEXW lpDateFmtEnumProcEx, LCID Locale, DWORD dwFlags);
```

### Reference 

- [MSDN EnumDateFormatsExA](https://docs.microsoft.com/en-us/windows/win32/api/winnls/nf-winnls-enumdateformatsexa)
- [MSDN EnumDateFormatsExW](https://docs.microsoft.com/en-us/windows/win32/api/winnls/nf-winnls-enumdateformatsexw)