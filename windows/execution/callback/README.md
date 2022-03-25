# Shellcode Loader

### Overview

Melakukan penyalahgunaan windows API untuk mengeksekusi shellcode sebagai callback.

Sebagian windows API menerima callback yang akan dijalankan untuk menangani objek atau memproses hasil operasi. Dengan menjalankan shellcode sebagai callback, kode menjadi lebih tersamarkan karena pemanggilan shellcode menjadi implisit.

Umumnya callback akan berjalan pada thread yang sama dengan thread yang memanggil fungsi windows API.