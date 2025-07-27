# Shellcode Loader

### Overview

Teknik dalam `storage` adalah teknik yang digunakan untuk menyimpan shellcode sebelum dijalankan di memory. Shellcode dapat disimpan secara tersemat atau tertanam dalam loader, atau berada di luar loader sehingga harus didapatkan terlebih dahulu.

### Catalog

Beberapa teknik `storage` yang diimplementasikan:

- [download-http](download-http): mengunduh shellcode dari HTTP
- [global](global): menyimpan shellcode pada bagian global area
- [resource](resource): menyimpan shellcode pada bagian resource
- [section](section): menyimpan shellcode sebagai section terpisah
- [stack](stack): menyimpan shellcode pada stack sebuah fungsi