# Shellcode Loader

Store shellcode as embedded resource in executable.

### Overview

Shellcode disimpan sebagai array of byte dan disematkan sebagai resource. Akses shellcode dilakukan dengan serangkaian operasi pembacaan resource.

Catatan: eksekusi shellcode untuk sample akan menggunakan teknik menjalankan shellcode sebagai thread terpisah.