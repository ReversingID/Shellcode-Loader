# Shellcode Loader

### Overview

Eksekusi shellcode sebagai thread terpisah dengan shared memory address (berbagi ruang memory antar thread dalam satu process). Terdapat beberapa fungsi Threading di Windows (public/internal) yang dapat dimanfaatkan untuk menjalankan thread. 

Secara garis besar, shellcode yang telah diekstrak akan disalin ke ruang memory yang telah dialokasikan. Alamat shellcode kemudian menjadi fungsi entrypoint bagi thread.