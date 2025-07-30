# Shellcode Loader

### Overview

Melakukan penyalahgunaan POSIX API, standard library, framework, dsb untuk mengeksekusi shellcode sebagai callback.

Fungsi yang dapat disalahgunakan pada POSIX lebih sedikit daripada Windows API.

Sebagian API menerima callback yang akan dijalankan untuk menangani objek atau memproses hasil operasi. Dengan menjalankan shellcode sebagai callback, kode menjadi lebih tersamarkan karena pemanggilan shellcode menjadi implisit.

Umumnya callback akan berjalan pada thread yang sama dengan thread yang memanggil fungsi.