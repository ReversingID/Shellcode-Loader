# Shellcode Loader

Store shellcode as global data (array).

### Overview

Shellcode disimpan sebagai array of byte pada segment global dan dapat diakses melalui suatu alamat memory yang konstan.

Catatan: eksekusi shellcode untuk sample akan menggunakan teknik menjalankan shellcode sebagai thread terpisah.