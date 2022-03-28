# Shellcode Loader

Abusing callback to run shellcode.

### Overview

Eksekusi shellcode dengan `EnumCalendarInfo`.

```c++
BOOL EnumCalendarInfoA (CALINFO_ENUMPROCA lpCalInfoEnumProc, LCID Locale, CALID Calendar, CALTYPE CalType);

BOOL EnumCalendarInfoW (CALINFO_ENUMPROCW lpCalInfoEnumProc, LCID Locale, CALID Calendar, CALTYPE CalType);
```

### Reference 

- [MSDN EnumCalendarInfoA](https://docs.microsoft.com/en-us/windows/win32/api/winnls/nf-winnls-enumcalendarinfoa)
- [MSDN EnumCalendarInfoW](https://docs.microsoft.com/en-us/windows/win32/api/winnls/nf-winnls-enumcalendarinfow)