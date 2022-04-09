# Shellcode Loader

Transform the shellcode with custom algorithm.

### Overview

Shellcode dienkripsi menggunakan XOR sederhana. Sebuah key disimpan sebagai byte pertama dan digunakan berulang untuk setiap byte shellcode.

Shellcode yang tersimpan memiliki format `[Key] [Encoded Shellcode]`.