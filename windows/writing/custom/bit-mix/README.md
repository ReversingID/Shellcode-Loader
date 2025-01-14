# Shellcode Loader

Transform the shellcode with custom algorithm.

### Overview

`Bit-mixing` adalah teknik atau proses manipulasi bit dalam sebuah data atau block data untuk mengacak atau mencampurkan bit-bit tersebut. Dalam kriptografi, terutama `hashing`, proses `bit-mixing` digunakan untuk meningkatkan kekuatan hash sehingga sulit diprediksi.

Proses `bit-mixing` dalam hal ini digunakan untuk mengacak shellcode dengan memanipulasi bit-bit melalui operasi XOR, AND, OR, shifting, dan rotation sehingga menghasilkan data yang berbeda.

Tidak ada batasan spesifik bagaimana pencampuran dilakukan. Dalam contoh ini, shellcode akan dianggap sebagai serangkaian pasangan byte dan pencampuran bit akan dilakukan untuk setiap pasang byte.

Secara spesifik, ini adalah algoritma yang diterapkan.

```
L' = (L & 0xF0) | (R & 0x0F)
R' = (L & 0x0F) | (R & 0xF0)

L = rotl(L', 3) ^ K
R = rotr(R', 3) ^ K
```
