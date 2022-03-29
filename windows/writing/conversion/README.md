# Shellcode Loader

### Overview

Melakukan penyalahgunaan windows API untuk menyalin shellcode.

Fungsi yang termasuk ke dalam kategori ini adalah fungsi yang melakukan konversi dari satu format ke format lain (misal, UTF-8 ke UNICODE). Umumnya fungsi memiliki argumen berupa input dan output buffer.

Shellcode yang akan diproses oleh fungsi-fungsi ini haruslah disimpan dalam format yang telah ditentukan. Dengan demikian, setiap fungsi mungkin memerlukan generator untuk mengubah (konversi) shellcode menjadi bentuk yang dapat diterima sebagai input fungsi.