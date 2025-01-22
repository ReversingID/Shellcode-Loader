# Shellcode Loader

Transform the shellcode with custom algorithm.

### Overview

`Bit-Mixing` adalah teknik atau proses manipulasi bit berupa pencampuran bit-bit dari blok data berbeda untuk menghasilkan blok data baru. Proses ini dilakukan dengan operasi `XOR`, `AND`, `OR`, `shifting`, dan `rotation`.

Penerapan `Bit-Mixing` dalam shellcode digunakan haruslah merupakan proses yang dapat dibalikkan (invertible).

`Cross-Over` adalah variasi pencampuran bit dengan menyambungkan potongan byte menjadi byte baru. Teknik ini didasarkan pada genetika terutama crossover pada kromosom.

Blok data terdiri atas dua komponen, `Left` dan `Right`. Ambil setengah byte dari `Left` dan kombinasikan dengan setengah byte dari `Right`. Kombinasi ini dapat berupa:
- `high(L) . low(R)` dan `high(R) . low(L)`
- `high(L) . high(R)` dan `low(L) . low(R)`

Pada kasus pertama, kita dapat menuliskan algoritma sebagai berikut:

```
low(X)  = X & 0x0F
high(X) = X & 0xF0

L' = high(L) | low(R)
R' = high(R) | low(L)
```

Sementara pada kasus kedua, kita perlu melakukannya sebagai berikut:

```
low(X)  = X & 0x0F
high(X) = X & 0xF0

L' = high(L)        | (high(R) >> 4)
R' = (low(L) << 4)  | low(R)
```

Namun terdapat beberapa kelemahan dalam algoritma ini. Apabila potongan byte yang bertukar merupakan nilai yang sama, maka proses cross-over tidak menghasilkan perubahan.

Pada proses pertama, misalnya, jika `low(L)` bernilai sama dengan `low(R)` maka operasi secara keseluruhan akan menghasilkan byte awal. Hal sama terjadi jika `low(L)` sama dengan `high(R)`.

Untuk mengatasi hal tersebut, maka kita dapat menambahkan operasi `ROTATE` dan `XOR` di akhir untuk menambah pengacakan.

Berikut adalah algoritma yang diterapkan pada contoh ini:

```
low(X)  = X & 0x0F
high(X) = X & 0xF0

L' = high(L) | low(R)
R' = high(R) | low(L)

L = rotl(L', 3) ^ K
R = rotr(R', 3) ^ K
```
