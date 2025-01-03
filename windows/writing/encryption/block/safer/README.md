# Shellcode Loader

Shellcode encryptoin.

### Overview

Enkripsi `SAFER+` (dari keluarga SAFER) dengan implementasi pribadi tanpa menggunakan API pihak ketiga.

`SAFER` merupakan block cipher sebagai salah satu kontestan pada project NESSIE. Algoritma ini memiliki beberapa opsi ukuran key, namun dalam contoh implementasi akan digunakan ukuran key 128-bit.

### References

- [Reversing.ID SAFER Reference](https://github.com/ReversingID/Crypto-Reference/tree/master/References/Modern/Block-Cipher/SAFER)
- [Reversing.ID SAFER Code](https://github.com/ReversingID/Crypto-Reference/blob/master/Codes/Cipher/Block/SAFER/SAFER.c)
- [Wikipedia SAFER](https://en.wikipedia.org/wiki/SAFER_(cipher))