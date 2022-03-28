# Shellcode Loader

Transform the shellcode with custom algorithm.

### Overview

Shellcode dienkripsi menggunakan XOR sederhana. Sebuah key disimpan sebagai byte pertama dan digunakan untuk mengenkripsi shellcode. Setiap selesai mengenkripsi byte, nilai key akan meningkat.

Shellcode yang tersimpan memiliki format `[Key] [Encoded Shellcode]`.