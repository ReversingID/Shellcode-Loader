# Shellcode Loader

### Overview

Teknik dalam `syscall` mengakses Windows NT API secara langsung melalui instruksi `syscall`, melewati lapisan Win32 dan stub ntdll.dll yang sering dijadikan target hook oleh EDR. Setiap teknik memerlukan `Syscall Service Number (SSN)` — angka yang mengidentifikasi fungsi kernel — yang kemudian dimasukkan ke register `EAX` sebelum instruksi `syscall` dieksekusi.

Perbedaan utama antarvarian terletak pada cara SSN diperoleh ketika stub ntdll telah dimodifikasi (di-hook) oleh EDR.

### Catalog

Daftar teknik `syscall` yang diimplementasikan:

- [hells-gate](hells-gate): membaca SSN langsung dari stub ntdll di memori; jika stub di-hook, baca dari ntdll.dll di disk sebagai fallback.
- [halos-gate](halos-gate): jika stub di-hook, inferensi SSN dari stub fungsi NT tetangga yang tidak di-hook (SSN bersifat sekuensial terhadap urutan alamat).
- [tartarus-gate](tartarus-gate): mendeteksi hook di byte 0 maupun byte 3 dari stub, kemudian gunakan neighbor scan untuk mendapatkan SSN.