# Shellcode Loader

Access the Windows API by dynamically loading.

### Overview

Resolve function dari DLL yang telah dimuat menggunakan `GetModuleHandle` dan `GetProcAddress`.

`GetModuleHandleA` mendapatkan handle dari DLL yang sudah dimuat oleh proses tanpa menambah reference count. Dikombinasikan dengan `GetProcAddress`, metode ini memungkinkan resolusi fungsi tanpa memuat ulang DLL. Cocok untuk DLL yang dijamin sudah ada di memori proses seperti `kernel32.dll` dan `ntdll.dll`.

```c++
HMODULE GetModuleHandleA (LPCSTR lpModuleName);

FARPROC GetProcAddress (HMODULE hModule, LPCSTR lpProcName);
```

### Reference

- [MSDN GetModuleHandleA](https://docs.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-getmodulehandlea)
- [MSDN GetProcAddress](https://docs.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-getprocaddress)
