# Shellcode Loader

Transform the shellcode with custom algorithm.

### Overview

Mengubah shellcode menjadi rangkaian karakter cetak (printable character) di ASCII, yakni bernilai pada rentang `0x20` hingga `0x7F`.

Algoritma ini bekerja dengan membagi setiap byte menjadi 2 nibble (4-bit) `L (Left)` dan `R (Right)` sehingga `B = L(B)<<4 | R(B)`.

Kemudian `L` dan `R` akan dipetakan ke rentang karakter cetak ASCII sebagai lower nibble dan sembarang nilai (0x2 - 0x6) sebagai high nibble.

Contoh:

```
B = 0x37
L = 0x3
R = 0x7
B = 0x3<<4 | 0x7 = 0x37

encoded = 0x23 0x47
```

Sehingga, shellcode akan berukuran 2x lipat ukuran semula.
