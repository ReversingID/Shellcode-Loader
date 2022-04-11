# Shellcode Loader

Abusing callback to run shellcode.

### Overview

Eksekusi shellcode dengan `EnumProps`.

```c++
int EnumPropsA (HWND hWnd, PROPENUMPROCA lpEnumFunc);

int EnumPropsW (HWND hWnd, PROPENUMPROCW lpEnumFunc);

BOOL SetPropA (HWND hWnd, LPCSTR lpString, HANDLE hData);

BOOL SetPropW (HWND hWnd, LPCWSTR lpString, HANDLE hData);

HANDLE RemovePropA (HWND hWnd, LPCSTR lpString);

HANDLE RemovePropW (HWND hWnd, LPCWSTR lpString);
```

### Reference 

- [MSDN EnumPropsA](https://docs.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-enumpropsa)
- [MSDN EnumPropsW](https://docs.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-enumpropsw)
- [MSDN SetPropA](https://docs.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-setpropa)
- [MSDN SetPropW](https://docs.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-setpropw)
- [MSDN RemovePropA](https://docs.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-removepropa)
- [MSDN RemovePropW](https://docs.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-removepropw)
- [MSDN GetTopWindow](https://docs.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-gettopwindow)