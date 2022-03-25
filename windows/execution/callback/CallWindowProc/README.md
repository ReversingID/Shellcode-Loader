# Shellcode Loader

Abusing callback to run shellcode.

### Overview

Eksekusi shellcode dengan `CallWindowProc`.

```c++
LRESULT CallWindowProcA (WNDPROC lpPrevWndFunc, HWND hWnd, UINT Msg, WPARAM wParam, LPARAM lParam);

LRESULT CallWindowProcW (WNDPROC lpPrevWndFunc, HWND hWnd, UINT Msg, WPARAM wParam, LPARAM lParam);
```

### Reference 

- [MSDN CallWindowProcA](https://docs.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-callwindowproca)
- [MSDN CallWindowProcW](https://docs.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-callwindowprocw)