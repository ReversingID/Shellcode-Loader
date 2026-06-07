# Shellcode Loader

Resolve function from shared library.

### Overview

Windows API diimplementasikan sebagai sebuah `shared library` (`DLL` atau `Dynamic Link Library`) yang mengekspos function dan diidentifikasi berdasarkan nama atau ID. Akses terhadap API dapat terjadi dengan resolusi statis, dimana saat compile nama library dan fungsi yang tepat akan didaftarkan di aplikasi. Sehingga, untuk memanggil fungsi aplikasi hanya perlu mendapatkan alamat yang tepat di library yang telah dimuat.

`Dynamic Load` merupakan teknik dimana pemanggilan terjadi pada library eksternal dan belum dimuat sebelumnya.

### Catalog

Daftar teknik `dynamic-load` yang diimplementasikan:

- [GetModuleHandle](GetModuleHandle): resolusi fungsi dari DLL yang sudah dimuat menggunakan `GetModuleHandle` dan `GetProcAddress`.
- [LdrGetProcedureAddress](LdrGetProcedureAddress): resolusi fungsi menggunakan API internal NTDLL `LdrGetProcedureAddress`, melewati lapisan Win32.
- [LoadLibrary](LoadLibrary): memuat DLL secara eksplisit menggunakan `LoadLibrary` lalu mendapatkan alamat fungsi dengan `GetProcAddress`.
- [manual-name](manual-name): resolusi fungsi dengan menelusuri PEB dan export table PE secara manual, membandingkan nama fungsi tanpa `GetProcAddress`.
- [manual-ordinal](manual-ordinal): resolusi fungsi dengan menelusuri PEB, mencocokkan nama DLL, lalu mengambil ekspor berdasarkan ordinal tanpa `GetProcAddress`.