# Shellcode Loader

Abusing callback to run shellcode.

### Overview

Eksekusi shellcode dengan `EnumLanguageGroupLocales`.

```c++
BOOL EnumLanguageGroupLocalesA (LANGGROUPLOCALE_ENUMPROCA lpLangGroupLocaleEnumProc, LGRPID LanguageGroup, DWORD dwFlags, LONG_PTR lParam);

BOOL EnumLanguageGroupLocalesW (LANGGROUPLOCALE_ENUMPROCW lpLangGroupLocaleEnumProc, LGRPID LanguageGroup, DWORD dwFlags, LONG_PTR lParam);
```

### Reference 

- [MSDN EnumLanguageGroupLocalesA](https://docs.microsoft.com/en-us/windows/win32/api/winnls/nf-winnls-enumlanguagegrouplocalesa)
- [MSDN EnumLanguageGroupLocalesW](https://docs.microsoft.com/en-us/windows/win32/api/winnls/nf-winnls-enumlanguagegrouplocalesw)