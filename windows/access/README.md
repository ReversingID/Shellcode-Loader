# Shellcode Loader

### Overview

Teknik dalam `access` mencakup variasi metode akses API atau function. Teknik-teknik ini tidak secara langsung mendemonstrasikan bagaimana eksekusi shellcode, namun berguna untuk mengeksekusi API yang digunakan dalam eksekusi shellcode (payload).

### Catalog

Daftar teknik `access` yang diimplementasikan:

- [dynamic-load](dynamic-load): resolusi fungsi dari shared library (DLL) secara dinamis pada saat runtime.
- [module-enumeration](module-enumeration): variasi teknik resolusi modul (DLL).
- [function-hash](function-hash): resolusi fungsi berdasarkan nilai hash dari nama fungsi, tanpa menyebutkan nama fungsi secara eksplisit.
- [syscalls](syscalls): pemanggilan NT API secara langsung melalui instruksi `syscall`, melewati stub yang di-hook oleh EDR.