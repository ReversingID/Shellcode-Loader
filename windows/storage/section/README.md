# Shellcode Loader

Store shellcode as separate section in executable.

### Overview

Shellcode disimpan sebagai array of byte pada section khusus dengan permission tertentu. Eksekusi shellcode dapat dilakukan secara langsung tanpa melakukan alokasi terpisah.

Catatan: eksekusi shellcode untuk sample akan menggunakan teknik menjalankan shellcode sebagai thread terpisah.