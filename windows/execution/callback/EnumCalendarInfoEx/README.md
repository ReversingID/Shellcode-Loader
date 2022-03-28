# Shellcode Loader

Abusing callback to run shellcode.

### Overview

Eksekusi shellcode dengan `EnumCalendarInfoEx`.

```c++
BOOL EnumCalendarInfoExA (CALINFO_ENUMPROCEXA lpCalInfoEnumProcEx, LCID Locale, CALID Calendar, CALTYPE CalType);

BOOL EnumCalendarInfoExW (CALINFO_ENUMPROCEXA lpCalInfoEnumProcEx, LCID Locale, CALID Calendar, CALTYPE CalType);
```

### Reference 

- [MSDN EnumCalendarInfoExA](https://docs.microsoft.com/en-us/windows/win32/api/winnls/nf-winnls-enumcalendarinfoexa)
- [MSDN EnumCalendarInfoExW](https://docs.microsoft.com/en-us/windows/win32/api/winnls/nf-winnls-enumcalendarinfoexw)