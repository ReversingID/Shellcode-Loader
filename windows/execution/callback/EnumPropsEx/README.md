# Shellcode Loader

Abusing callback to run shellcode.

### Overview

Eksekusi shellcode dengan `EnumPropsEx`.

```c++
int EnumPropsExA (HWND hWnd, PROPENUMPROCEXA lpEnumFunc, LPARAM lParam);

int EnumPropsExW (HWND hWnd, PROPENUMPROCEXW lpEnumFunc, LPARAM lParam);

BOOL SetPropA (HWND hWnd, LPCSTR lpString, HANDLE hData);

BOOL SetPropW (HWND hWnd, LPCWSTR lpString, HANDLE hData);

HANDLE RemovePropA (HWND hWnd, LPCSTR lpString);

HANDLE RemovePropW (HWND hWnd, LPCWSTR lpString);
```

### Reference 

- [MSDN EnumPropsExA](https://docs.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-enumpropsexa)
- [MSDN EnumPropsExW](https://docs.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-enumpropsexw)
- [MSDN SetPropA](https://docs.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-setpropa)
- [MSDN SetPropW](https://docs.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-setpropw)
- [MSDN RemovePropA](https://docs.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-removepropa)
- [MSDN RemovePropW](https://docs.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-removepropw)
- [MSDN GetTopWindow](https://docs.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-gettopwindow)