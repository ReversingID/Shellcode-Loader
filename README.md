# Shellcode Loader

Open repository for learning dynamic shellcode loading.

### Disclaimer

For english version, see [README.EN.md](README.EN.md)

Repository ini digunakan untuk menghimpun informasi tentang teknik memuat shellcode ke memory yang digunakan oleh implant. Repository ini terbuka untuk publik, dapat diakses oleh siapa saja baik oleh internal maupun di luar komunitas `Reversing.ID`.

### Content

Untuk memudahkan klasifikasi, repository ini dibagi menjadi beberapa kategori berdasarkan platform (OS) dan teknik memuat kode. Setiap direktori mengacu kepada sebuah teknik dan berisi informasi singkat serta implementasi dalam bahasa pemrograman tertentu (umumnya C/C++).

Catatan: teknik-teknik akan difokuskan kepada arsitektur x86.

### Shellcode Overview

`Shellcode` adalah potongan kode/instruksi dengan tujuan spesifik untuk melakukan aksi tertentu. Dalam eksploitasi shellcode digunakan sebagai payload (muatan) untuk disuntikkan ke suatu sistem dengan batasan tertentu. 

Secara teori shellcode dapat melakukan aksi apapun. Awalnya shellcode hanyalah instruksi untuk memanggil shell. Shellcode kemudian berkembang dan memiliki tujuan bervariasi seperti menciptakan user, menghapus data, dll.

Untuk melihat kumpulan shellcode, kunjungi [shellcodes repository](https://github.com/ReversingID/shellcodes).

Untuk melakukan penyuntikan shellcode ke process, kunjungi [injection repository](https://github.com/ReversingID/injection).

Untuk penyederhanaan, shellcode yang digunakan akan dibatasi hanya kepada kode berikut:

```
# 9090CCC3

0000:  90      nop
0001:  90      nop
0002:  CC      in3
0003:  c3      ret
```

### Techniques

Repository ini akan membahas proses dasar dalam sebuah pemuatan shellcode, yakni:
- `allocation`: strategi alokasi memory untuk menampung shellcode (sebagai kode).
- `storage`: strategi penyimpanan shellcode.
- `execution`: strategi eksekusi shellcode.
- `writing`: strategi menulis kode ke memory (sendiri), baik secara langsung maupun melalui proses transformasi tertentu.

Sebagian teknik memanfaatkan API yang disediakan oleh OS, baik secara langsung maupun tak langsung.