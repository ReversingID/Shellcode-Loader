# Shellcode Loader

Abusing callback to run shellcode.

### Overview

Eksekusi shellcode dengan `EnumFontFamilies`.

```c++
int EnumFontFamiliesA (HDC hdc, LPCSTR lpLogfont, FONTENUMPROCA lpProc, LPARAM lParam);

int EnumFontFamiliesW (HDC hdc, LPCWSTR lpLogfont, FONTENUMPROCW lpProc, LPARAM lParam);

HDC GetDC (HWND hWnd);
```

### Reference 

- [MSDN EnumFontFamiliesA](https://docs.microsoft.com/en-us/windows/win32/api/wingdi/nf-wingdi-enumfontfamiliesa)
- [MSDN EnumFontFamiliesW](https://docs.microsoft.com/en-us/windows/win32/api/wingdi/nf-wingdi-enumfontfamiliesw)
- [MSDN GetDC](https://docs.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-getdc)