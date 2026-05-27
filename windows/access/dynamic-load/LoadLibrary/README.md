# Shellcode Loader

Access the Windows API by dynamically loading.
Resolve function from DLL using LoadLibrary and GetProcAddress.

### Overview

Resolve function dengan memuat DLL menggunakan `LoadLibrary` dan `GetProcAddress`.

`LoadLibraryA` memuat sebuah DLL ke dalam proses saat runtime meski belum sebelumnya dimuat. `GetProcAddress` kemudian digunakan untuk mendapatkan alamat fungsi berdasarkan nama. Keduanya adalah fungsi Win32 dari `kernel32.dll`.

```c++
HMODULE LoadLibraryA (LPCSTR lpLibFileName);

FARPROC GetProcAddress (HMODULE hModule, LPCSTR lpProcName);
```

### Reference

- [MSDN LoadLibraryA](https://docs.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-loadlibrarya)
- [MSDN GetProcAddress](https://docs.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-getprocaddress)
