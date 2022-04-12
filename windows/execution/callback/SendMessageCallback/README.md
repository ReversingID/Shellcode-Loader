# Shellcode Loader

Abusing callback to run shellcode.

### Overview

Eksekusi shellcode dengan `SendMessageCallback`. Fungsi ini akan mengirimkan sebuah message ke window dan menjalankan callback apabila message diproses. Dengan memproses message secara manual, callback akan dipicu.

```c++
BOOL SendMessageCallbackA (HWND hWnd, UINT Msg, WPARAM wParam, LPARAM lParam, SENDASYNCPROC lpResultCallBack, ULONG_PTR dwData);

BOOL SendMessageCallbackW (HWND hWnd, UINT Msg, WPARAM wParam, LPARAM lParam, SENDASYNCPROC lpResultCallBack, ULONG_PTR dwData);
```

### Reference 

- [MSDN SendMessageCallbackA](https://docs.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-sendmessagecallbacka)
- [MSDN SendMessageCallbackW](https://docs.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-sendmessagecallbackw)