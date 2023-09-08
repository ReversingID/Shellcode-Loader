# Shellcode Loader

Transforming the shellcode by byte substitution.

### Overview

Menggunakan enkripsi klasik Hill Cipher untuk mengganti byte melalui perkalian matriks untuk setiap pasang byte. Rumus yang digunakan untuk sample ini adalah matriks `[[197, 0], [0, 173]]` dan matriks invers `[[13, 0], [0, 37]]`