# Shellcode Loader

### Overview

Eksekusi shellcode dengan cast shellcode sebagai function/procedur dan memanggil shellcode secara langsung. Shellcode akan dieksekusi pada thread yang sama dengan thread pemanggil.

Teknik `invoke` adalah satu primitif eksekusi berupa transfer kontrol langsung ke alamat shellcode. Implementasi teknik bergantung pada masing-masing bahasa, dimana pointer ke shellcode akan dianggap sebagai sebuah fungsi untuk kemudian dipanggil. Perbedaan utama terletak pada sintaks cast/delegate, mekanisme FFI, dan penanganan memori executable.

Katalog ini mencantumkan bahasa pemrograman yang didukung, bukan variasi API Windows.

### Catalog

**Bahasa pemrograman**

- [c++](c++): cast `void*` ke function pointer (`int (*)()`) lalu panggil langsung.
- [c#](c#): `Marshal.GetDelegateForFunctionPointer<T>` setelah alokasi dan proteksi via P/Invoke.
- [go](go): `syscall.Syscall` dengan alamat shellcode sebagai entry point.
- [nim](nim): `cast[proc(){.nimcall.}]` pada buffer yang sudah di-`VirtualProtect`.
- [python](python): `ctypes.CFUNCTYPE` untuk membungkus alamat memori menjadi callable Python.
- [rust](rust/with-mmap): `mem::transmute` ke `fn()` pada buffer RWX/RX yang dialokasikan via crate `mmap`.

### Related

- [execution/asm-jmp](../asm-jmp): lompatan assembly langsung ke alamat shellcode tanpa cast function pointer.
