# Shellcode Loader

Open repository for learning dynamic shellcode loading.

### Disclaimer

Repository ini digunakan untuk menghimpun informasi tentang teknik memuat shellcode ke memory yang digunakan oleh implant. Repository ini terbuka untuk publik, dapat diakses oleh siapa saja baik oleh internal maupun di luar komunitas `Reversing.ID`.

### Content

Untuk memudahkan klasifikasi, repository ini dibagi menjadi beberapa direktori berdasarkan platform (OS), bahasa, dan teknik memuat kode.

Catatan: teknik-teknik akan difokuskan kepada arsitektur x86.

### Shellcode Overview

`Shellcode` adalah potongan kode/instruksi dengan tujuan spesifik untuk melakukan aksi tertentu. Dalam eksploitasi shellcode digunakan sebagai payload (muatan) untuk disuntikkan ke suatu sistem dengan batasan tertentu. 

Secara teori shellcode dapat melakukan aksi apapun. Awalnya shellcode hanyalah instruksi untuk memanggil shell. Shellcode kemudian berkembang dan memiliki tujuan bervariasi seperti menciptakan user, menghapus data, dll.

Untuk melihat kumpulan shellcode, kunjungi [shellcodes repository](https://github.com/ReversingID/shellcodes).

Untuk penyederhanaan, shellcode yang digunakan akan dibatasi hanya kepada kode berikut:

```
# 9090CCC3

0000:  90      nop
0001:  90      nop
0002:  CC      in3
0003:  c3      ret
```