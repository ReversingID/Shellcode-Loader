# Shellcode Loader

### Overview

Tahap `execution` adalah tahap menjalankan shellcode, baik secara langsung maupun tak langsung.

Teknik eksekusi dapat dibagi menjadi beberapa kategori berdasarkan karakteristik eksekusi:

- callback: menyalahgunakan API untuk memanggil shellcode sebagai callback.
- event: memanfaatkan trigger event
- exception: menyalahgunakan sistem exception handling.
- fiber: eksekusi shellcode sebagai fiber baru
- [invoke](invoke): eksekusi shellcode secara langsung tanpa API.
- thread: eksekusi shellcode sebagai thread baru
