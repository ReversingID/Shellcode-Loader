# Shellcode Loader

Transform the shellcode with custom algorithm.

### Overview

Shellcode dienkripsi menggunakan XOR sederhana. Shellcode akan dibagi menjadi beberapa N blok berisi maksimal S-byte. Setiap blok akan didahului dengan sebuah key yang digunakan untuk mengenkripsi blok tersebut.

Shellcode yang tersimpan memiliki format sebagai berikut:

```
[N] [B] [[Key-1] [Encoded Shellcode-1]] [[Key-2] [Encoded Shellcode-2]] ... [[Key-N] [Encoded Shellcode-N]].
```