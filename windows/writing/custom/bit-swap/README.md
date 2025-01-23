# Shellcode Loader

Transform the shellcode with custom algorithm.

### Overview

`Bit-Mixing` adalah teknik atau proses manipulasi bit berupa pencampuran bit-bit dari blok data berbeda untuk menghasilkan blok data baru. Proses ini dilakukan dengan operasi `XOR`, `AND`, `OR`, `shifting`, dan `rotation`.

Penerapan `Bit-Mixing` dalam shellcode digunakan haruslah merupakan proses yang dapat dibalikkan (invertible).

`Swap` adalah variasi dari pencampuran bit dengan menukar bit-bit dari block data berbeda. Teknik ini dapat pula disebut sebagai `Cross-Over` yang lebih generik.

Blok data terdiri atas dua komponen, `Left` dan `Right`. Ambil `N` bit dari posisi `P` dari `Left` dan `Right`, tukar kedua potongan bit tersebut.

Berikut adalah algoritma yang diterapkan, ambil `N=3` bit dari posisi `P=2` dari `Left` dan `Right`:

```
extract(X) = X & 0x1E
clear(x)   = X & 0xE1

L' = clear(L) | extract(R)
R' = clear(R) | extract(L)
```