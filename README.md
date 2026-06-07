# Shellcode Loader

Repositori terbuka untuk pembelajaran tentang dynamic shellcode loading.

**Bahasa:** Bahasa Indonesia (default) | [English](README.EN.md)

---

## Pengenalan Singkat

Repository ini menghimpun informasi tentang teknik memuat shellcode ke memory yang digunakan oleh implant. Repositori ini terbuka untuk publik, dapat diakses oleh siapa saja baik oleh internal maupun di luar komunitas `Reversing.ID`.

### Apa itu Shellcode?

`Shellcode` adalah potongan kode/instruksi dengan tujuan spesifik untuk melakukan aksi tertentu. Dalam eksploitasi, shellcode digunakan sebagai payload (muatan) untuk disuntikkan ke suatu sistem dengan batasan tertentu.

Secara teori shellcode dapat melakukan aksi apapun. Awalnya shellcode hanyalah instruksi untuk memanggil shell. Shellcode kemudian berkembang dan memiliki tujuan bervariasi seperti menciptakan user, menghapus data, dll.

**Contoh shellcode yang digunakan:**
```
# 9090CCC3

0000:  90      nop
0001:  90      nop
0002:  CC      int3
0003:  c3      ret
```

---

## Teknik Dasar

Repository ini membahas proses dasar dalam pemuatan shellcode, yakni:

| Teknik | Deskripsi |
|--------|-----------|
| **allocation** | Strategi alokasi memory untuk menampung shellcode sebagai kode executable |
| **storage** | Strategi penyimpanan shellcode sebelum dieksekusi |
| **execution** | Strategi eksekusi shellcode dari memory |
| **writing** | Strategi menulis/memodifikasi kode ke memory, baik langsung atau melalui transformasi |
| **permission** | Manajemen permission/attribute memory untuk memungkinkan eksekusi |
| **access** | variasi akses API yang digunakan dalam proses loading (terutama Windows) |

Sebagian teknik memanfaatkan API yang disediakan oleh OS, baik secara langsung maupun tak langsung.

---

## Struktur Repository

```
Shellcode-Loader/
├── linux/                  # Teknik untuk Linux
│   ├── allocation/        # Memory allocation
│   ├── storage/          # Shellcode storage
│   ├── execution/        # Code execution
│   ├── writing/          # Code writing
│   └── permission/       # Permission management
│
├── windows/              # Teknik untuk Windows
│   ├── access/           # Windows API reference
│   ├── allocation/       # Memory allocation
│   ├── storage/          # Shellcode storage
│   ├── execution/        # Code execution (dengan sub-teknik)
│   │   ├── asm-jmp/
│   │   ├── callback/
│   │   ├── event/
│   │   ├── fiber/
│   │   ├── invoke/
│   │   └── thread/
│   ├── writing/          # Code writing
│   └── permission/       # Permission management
│
├── README.md             # Dokumentasi ini
├── README.EN.md          # Dokumentasi dalam English
├── CONTRIBUTING.md       # Panduan kontribusi
├── RESOURCES.md          # Indeks lengkap dan referensi
└── .gitignore           # Git ignore rules
```

---

## Quick Start

### 1. Mulai Dari Sini
- **Pemula?** Baca [Pengenalan Shellcode](#apa-itu-shellcode) di atas
- **Ingin melihat semua teknik?** Lihat [RESOURCES.md](RESOURCES.md)
- **Ingin kontribusi?** Baca [CONTRIBUTING.md](CONTRIBUTING.md)

### 2. Pilih Platform
- **Linux:** Buka direktori [linux/](linux/)
- **Windows:** Buka direktori [windows/](windows/)

### 3. Pilih Teknik
Setiap direktori teknik berisi:
- `README.md` - Dokumentasi teknik
- Direktori (misal `c++/`) berisi implementasi kode di bahasa tertentu
- Contoh dan penjelasan

---

## Catatan

- Teknik-teknik dalam repository ini difokuskan pada arsitektur x86 (dan juga x64), kecuali dinyatakan lain
- Dokumentasi dan implementasi dalam Bahasa Indonesia dengan versi English tersedia
- Repository ini adalah sumber edukasi terbuka untuk komunitas keamanan siber

---

## Kontribusi

Kami menyambut kontribusi dari komunitas! Untuk panduan lengkap tentang cara berkontribusi:
- Baca [CONTRIBUTING.md](CONTRIBUTING.md) (Bahasa Indonesia)
- Baca [CONTRIBUTING.EN.md](CONTRIBUTING.EN.md) (English)

---

## Disclaimer

Repository ini digunakan untuk tujuan edukasi dan penelitian keamanan siber. Semua teknik dan kode dalam repository ini adalah untuk pembelajaran dan investigasi keamanan yang sah. Pengguna bertanggung jawab atas penggunaan informasi dalam repository ini dan harus mematuhi semua hukum dan regulasi yang berlaku di yurisdiksi mereka.