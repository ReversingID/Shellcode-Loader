# Shellcode Loader

### Overview

Teknik dalam `storage` adalah teknik yang digunakan untuk menyimpan shellcode sebelum dijalankan di memory. Shellcode dapat disimpan secara tersemat atau tertanam dalam loader, atau berada di luar loader sehingga harus didapatkan terlebih dahulu.

### Catalog

Beberapa teknik `storage` yang diimplementasikan:

- [stack](stack): menyimpan shellcode pada stack sebuah fungsi.