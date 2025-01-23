# Shellcode Loader

Transform the shellcode with custom algorithm.

### Overview

Melakukan `XOR` secara berantai antara byte sekarang dengan byte sebelumnya. 

Teknik ini didasarkan pada mode operasi `CBC (Cipher Block)` pada enkripsi block cipher. Pada `CBC`, setiap block plaintext akan di-XOR dengan block ciphertext sebelumnya sebelum dilakukan enkripsi. Blok awal akan dioperasikan dengan sebuah blok bernama `IV (Initialization Vector)`. Sehingga, dapat kita tulis sebagai berikut:

```
C[i] = Enc(P[i] ^ C[i - 1], K)
C[0] = Enc(P[0] ^ IV, K)
```

Sementara pada teknik ini, operasi berada pada level byte. Setiap byte akan di-XOR dengan byte ciphertext sebelumnya. Adapun kunci awal (genesis) merupakan byte pertama dalam shellcode yang tidak mengalami enkripsi.

```
C[i] = P[i] ^ C[i - 1]
C[0] = P[0]
```

Variasi lain adalah dengan menggunakan bilangan acak sebagai genesis key (atau juga `IV`), sehingga byte awal shellcode akan dienkripsi dengan byte tersebut.

```
C[i] = P[i] ^ C[i - 1]
C[0] = P[0] ^ K
```