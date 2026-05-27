# Shellcode Loader

Access the Windows API by dynamically loading.

### Overview

Resolve function dengan `LdrGetProcedureAddress` dari NTDLL.

`LdrGetProcedureAddress` merupakan fungsi internal NTDLL yang digunakan `GetProcAddress` secara internal. Menggunakan API ini secara langsung melewati lapisan Win32 dan mengakses loader NTDLL secara langsung. Fungsi menerima nama melalui struktur `ANSI_STRING` sehingga tidak ada string nama fungsi literal di panggilan.

```c++
NTSTATUS LdrGetProcedureAddress (
    HMODULE       ModuleHandle,
    PANSI_STRING  FunctionName,
    WORD          Ordinal,
    PVOID        *FunctionAddress
);
```

### Reference

- [NTInternals LdrGetProcedureAddress](http://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FNT%20Loader%2FLdrGetProcedureAddress.html)
