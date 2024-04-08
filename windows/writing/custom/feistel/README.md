# Shellcode Loader

Transform the shellcode with custom algorithm.

### Overview

Menggunakan prinsip `Feistel Network` untuk mengenkripsi shellcode. Sebuah key disimpan sebagai byte eprtama dan digunakan berulang untuk setiap operasi pada Feistel.

Shellcode yang tersimpan memiliki format `[Key] [Encoded Shellcode]`.

Penerapan Feistel Network dilakukan terhadap setiap pasang byte. Ambil 2 byte yakni L dan R. Pada setiap Feistel, lakukan perhitungan:

L[i+1] = R[i]
R[i+1] = L[i] xor Key