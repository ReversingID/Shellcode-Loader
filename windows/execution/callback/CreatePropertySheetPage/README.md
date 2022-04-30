# Shellcode Loader

Abusing callback to run shellcode.

### Overview

Eksekusi shellcode dengan `CreatePropertySheetPage`.

```c++
HPROPSHEETPAGE CreatePropertySheetPageA (LPCPROPSHEETPAGEA constPropSheetPagePointer);

HPROPSHEETPAGE CreatePropertySheetPageW (LPCPROPSHEETPAGEW constPropSheetPagePointer);
```

### Reference 

- [MSDN CreatePropertySheetPageA](https://docs.microsoft.com/en-us/windows/win32/api/prsht/nf-prsht-createpropertysheetpagea)
- [MSDN CreatePropertySheetPageW](https://docs.microsoft.com/en-us/windows/win32/api/prsht/nf-prsht-createpropertysheetpagew)
- [MSDN structure PROPSHEETPAGE](https://docs.microsoft.com/en-us/windows/win32/controls/pss-propsheetpage)