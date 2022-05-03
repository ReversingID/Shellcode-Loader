# Shellcode Loader

Abusing callback to run shellcode.

### Overview

Eksekusi shellcode dengan `DialogBoxIndirectParam`.

```c++
INT_PTR DialogBoxIndirectParamA (HINSTANCE hInstance, LPCDLGTEMPLATEA hDialogTemplate, HWND hWndParent, DLGPROC lpDialogFunc, LPARAM dwInitParam);

INT_PTR DialogBoxIndirectParamW (HINSTANCE hInstance, LPCDLGTEMPLATEW hDialogTemplate, HWND hWndParent, DLGPROC lpDialogFunc, LPARAM dwInitParam);
```

### Reference 

- [MSDN DialogBoxIndirectParamA](https://docs.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-dialogboxindirectparama)
- [MSDN DialogBoxIndirectParamW](https://docs.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-dialogboxindirectparamw)