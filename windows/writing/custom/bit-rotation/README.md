# Shellcode Loader

Transform the shellcode with custom algorithm.

### Overview

`Bit-Mixing` adalah teknik atau proses manipulasi bit berupa pencampuran bit-bit dari blok data berbeda untuk menghasilkan blok data baru. Proses ini dilakukan dengan operasi `XOR`, `AND`, `OR`, `shifting`, dan `rotation`.

Penerapan `Bit-Mixing` dalam shellcode digunakan haruslah merupakan proses yang dapat dibalikkan (invertible).

`Rotation` adalah variasi dari pencampuran bit dengan melakukan rotasi bit-bit (kiri atau kanan) pada level byte maupun gabungan byte.

Berikut adalah contoh variasi jika rotation dilakukan pada level byte

```
L = rotl(L, 3)
R = rotr(R, 5)
```

Variasi lain jika rotasi dilakukan pada gabungan byte.

```
X  = (L << 8) | R
X' = rotl(X, 7)

L = L' >> 8
R = R' & 0xFF
```

Variasi lain adalah gabungan dari keduanya, yakni melakukan rotasi di level byte dan gabungan byte.

```
L' = rotl(L, 3)
R' = rotr(R, 7)

X = (L' << 8) | R'
X' = rotl(X, 5)

L = L' >> 8
R = R' & 0xFF
```

Bit rotation dapat pula dilakukan secara berulang atau beberapa `round`, dengan masing-masing `round` memiliki rumus rotasi tersendiri.

Sama seperti `Cross-Over`, `Rotation` juga memiliki kelemahan. Jika `Left` dan `Right` merupakan nilai yang sama atau bit yang dipertukarkan memiliki nilai yang sama, maka proses rotasi tidak akan menghasilkan perubahan.

Untuk mengatasi hal tersebut, maka kita dapat menambahkan operasi `ROTATE` dan `XOR` di akhir untuk menambah pengacakan.