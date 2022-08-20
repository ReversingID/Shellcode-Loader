# Shellcode Loader

Abusing callback to run shellcode.

### Overview

Eksekusi shellcode dengan `PropertySheet`.

```c++
INT_PTR PropertySheetA (LPCPROPSHEETHEADERA header);

INT_PTR PropertySheetW (LPCPROPSHEETHEADERW header);
```

### Reference 

- [MSDN PropertySheetA](https://docs.microsoft.com/en-us/windows/win32/api/prsht/nf-prsht-propertysheeta)
- [MSDN PropertySheetW](https://docs.microsoft.com/en-us/windows/win32/api/prsht/nf-prsht-propertysheetw)
- [MSDN structure PROPSHEETHEADER](https://docs.microsoft.com/en-us/windows/win32/controls/pss-propsheetheader)