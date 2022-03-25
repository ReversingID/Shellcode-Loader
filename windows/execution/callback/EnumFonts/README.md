# Shellcode Loader

Abusing callback to run shellcode.

### Overview

Eksekusi shellcode dengan `EnumFonts`.

```c++
int EnumFontsA (HDC hdc, LPCSTR lpLogfont, FONTENUMPROCA lpProc, LPARAM lParam);

int EnumFontsW (HDC hdc, LPCWSTR lpLogfont, FONTENUMPROCW lpProc, LPARAM lParam);

HDC GetDC (HWND hWnd);
```

### Reference 

- [MSDN EnumFontsA](https://docs.microsoft.com/en-us/windows/win32/api/wingdi/nf-wingdi-enumfontsa)
- [MSDN EnumFontsW](https://docs.microsoft.com/en-us/windows/win32/api/wingdi/nf-wingdi-enumfontsw)
- [MSDN GetDC](https://docs.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-getdc)