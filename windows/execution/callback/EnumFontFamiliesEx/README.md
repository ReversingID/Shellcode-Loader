# Shellcode Loader

Abusing callback to run shellcode.

### Overview

Eksekusi shellcode dengan `EnumFontFamiliesEx`.

```c++
int EnumFontFamiliesExA(HDC hdc, LPLOGFONTA lpLogfont, FONTENUMPROCA lpProc, LPARAM lParam, DWORD dwFlags);

int EnumFontFamiliesExA(HDC hdc, LPLOGFONTW lpLogfont, FONTENUMPROCW lpProc, LPARAM lParam, DWORD dwFlags);

HDC GetDC (HWND hWnd);
```

### Reference 

- [MSDN EnumFontFamiliesExA](https://docs.microsoft.com/en-us/windows/win32/api/wingdi/nf-wingdi-enumfontfamiliesexa)
- [MSDN EnumFontFamiliesExW](https://docs.microsoft.com/en-us/windows/win32/api/wingdi/nf-wingdi-enumfontfamiliesexw)
- [MSDN GetDC](https://docs.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-getdc)