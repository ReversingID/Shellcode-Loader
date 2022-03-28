# Shellcode Loader

Abusing callback to run shellcode.

### Overview

Eksekusi shellcode dengan `EnumCalendarInfoExEx`.

```c++
BOOL EnumCalendarInfoExEx (CALINFO_ENUMPROCEXEX pCalInfoEnumProcExEx, LPCWSTR lpLocaleName, CALID Calendar, LPCWSTR lpReserved, CALTYPE CalType, LPARAM lParam);
```

### Reference 

- [MSDN EnumCalendarInfoExEx](https://docs.microsoft.com/en-us/windows/win32/api/winnls/nf-winnls-enumcalendarinfoexex)