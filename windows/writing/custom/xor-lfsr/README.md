# Shellcode Loader

Transform the shellcode with custom algorithm.

### Overview

Melakukan operasi XOR terhadap shellcode dengan sebuah nilai yang dihasilkan dari `LFSR (Linear Feedback Shift Register)`. Rangkaian byte yang dihasilkan dari `LFSR` merupakan nilai pseudo-random, sehingga setiap byte shellcode akan di-XOR dengan nilai yang berbeda.

`LFSR` menggunakan sebuah nilai (`seed`), yang dapat berupa sembarang byte. Dalam hal ini, seed dapat berupa sebuah byte yang secara khusus diberikan, atau dapat pula merupakan byte pertama shellcode.

Pada contoh ini, shellcode akan disimpan dengan format berikut: `[Seed] [Encoded Shellcode]`.