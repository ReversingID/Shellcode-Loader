# Shellcode Loader

### Overview

Teknik dalam `writing` adalah metode transformasi shellcode yang tersimpan. Shellcode yang tersimpan secara plain berpotensi tinggi untuk terdeteksi sehingga shellcode harus diacak untuk menyamarkannya. Untuk mendapatkan shellcode kembali, maka proses transformasi dilakukan sebelum atau saat menulis shellcode ke area yang ditentukan.

Teknik `writing` dapat dibagi menjadi beberapa kategori berdasarkan karakteristik:

- [compression](compression): kompresi terhadap shellcode untuk mengurangi ukuran.
- [conversion](conversion): mengubah representasi shellcode menjadi bentuk yang umum.
- [copy](copy): menyalin shellcode menggunakan beberapa fungsi tanpa adanya transformasi tambahan.
- [custom](custom): teknik-teknik unik di luar kategori yang ada.
- [encryption](encryption): enkripsi shellcode dengan algoritma enkripsi simetris atau asimetris.
- [permutation](permutation): penyusunan ulang byteberdasarkan aturan semi-acak.
- [substitution](substitution): mengganti byte berdasarkan pemetaan.