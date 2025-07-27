# Shellcode Loader

### Overview

Teknik `execution` adalah teknik menjalankan shellcode, baik secara langsung maupun tak langsung.

Teknik eksekusi dapat dibagi menjadi beberapa kategori berdasarkan karakteristik eksekusi:

- [asm-jmp](asm-jmp): lompat ke alamat shellcode secara langsung menggunakan intruksi assembly.
- [callback](callback): menyalahgunakan API untuk memanggil shellcode sebagai callback.
- [event](event): memanfaatkan trigger event
- [exception](exception): menyalahgunakan sistem exception handling.
- [fiber](fiber): eksekusi shellcode sebagai fiber baru
- [invoke](invoke): eksekusi shellcode secara langsung tanpa API.
- [thread](thread): eksekusi shellcode sebagai thread baru
