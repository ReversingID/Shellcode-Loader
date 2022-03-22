# Shellcode Loader

Store shellcode as local data in stack (array).

### Overview

Shellcode disimpan sebagai array of byte pada stack, dengan karakteristik adanya operasi push. Array dapat diakses melalui alamat memory relatif terhadap pointer.

Catatan: eksekusi shellcode untuk sample akan menggunakan teknik menjalankan shellcode sebagai thread terpisah.