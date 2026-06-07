# Berkontribusi pada Shellcode-Loader

Terima kasih telah tertarik untuk berkontribusi pada Shellcode-Loader! Repositori ini adalah sumber daya edukasi terbuka untuk komunitas keamanan siber.

## Tujuan Repository

Shellcode-Loader adalah repositori referensi yang menghimpun teknik-teknik memuat shellcode ke memory. Repositori ini dirancang untuk:
- Menyediakan dokumentasi komprehensif tentang berbagai teknik loading shellcode
- Memberikan implementasi praktis dalam bahasa C/C++
- Menjadi sumber pembelajaran bagi peneliti keamanan dan profesional reverse engineering

Untuk informasi lebih lanjut, lihat [README.md](README.md).

## Cara Berkontribusi

### 1. Fork dan Clone
Fork repositori ini ke akun GitHub Anda, kemudian clone ke lokal machine:
```bash
git clone https://github.com/YOUR_USERNAME/Shellcode-Loader.git
cd Shellcode-Loader
```

### 2. Buat Branch Baru
Buat branch dengan nama deskriptif untuk perubahan Anda:
```bash
git checkout -b add/nama-teknik
git checkout -b fix/deskripsi-singkat
git checkout -b improve/dokumentasi
```

### 3. Buat Perubahan
Ikuti konvensi berikut dalam membuat perubahan:

#### Struktur Direktori dan Konvensi Penamaan
```
platform/
  └── teknik/                   # allocation, storage, execution, writing, etc
      ├── README.md             # Dokumentasi teknik
      ├── c++/                  # Implementasi c++ (misal)
      │   └── code.cpp
      └── subteknik/            # Sub-kategori jika ada
          └── README.md
```

#### Konvensi Penamaan File
- Gunakan lowercase untuk nama direktori teknik secara umum. Jika nama direktori adalah API, sesuaikan lowercase dan uppercase dengan nama fungsi tersebut.
- Gunakan `code` sebagai nama file sample (misal `code.cpp`).
- Gunakan strip atau underscore untuk pemisah: `my-technique/`
- Hindari spasi dalam nama file

#### Template untuk Teknik Baru

Ketika menambahkan teknik baru, ikuti struktur README berikut:

```markdown
# [Nama Teknik]

### Overview
Penjelasan singkat tentang teknik ini. Apa tujuannya? Kapan digunakan?

### How It Works
Penjelasan mendalam tentang cara kerja teknik. Include diagram atau flowchart jika diperlukan.

### Implementation
Deskripsi implementasi dalam kode, API yang digunakan, dan batasan.

### Advantages
- Keuntungan 1
- Keuntungan 2

### Disadvantages
- Kekurangan 1
- Kekurangan 2

### Code Example
```c
// Code snippet here
```

### References
- Link ke dokumentasi API
- Link ke teknik related
- Paper atau resource lainnya
```

### 4. Panduan Coding (C/C++)

#### Style Guide
- Ikuti GNU C style atau K&R style
- Gunakan 4 spasi untuk indentasi (bukan tab)
- Penamaan fungsi: lowercase dengan underscore (snake_case)
- Penamaan konstanta: UPPERCASE dengan underscore
- Penamaan tipe: PascalCase

#### Contoh Format Kode
```c
#include <stdio.h>
#include <stdlib.h>
#include <windows.h>

// Konstanta
#define SHELLCODE_SIZE 4

// Struktur
typedef struct {
    DWORD value;
    char  name[50];
} MyStruct;

// Fungsi
void execute_shellcode(unsigned char *shellcode, size_t size) {
    LPVOID alloc = VirtualAlloc(NULL, size, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (!alloc) {
        printf("Allocation failed\n");
        return;
    }
    
    memcpy(alloc, shellcode, size);
    ((void(*)())alloc)();
    
    VirtualFree(alloc, size, MEM_RELEASE);
}
```

#### Error Handling
- Selalu periksa return value dari API calls
- Berikan error messages yang informatif
- Dokumentasi kondisi error dalam komentar

### 5. Dokumentasi

#### README Dalam Setiap Teknik
- Gunakan Bahasa Indonesia sebagai default
- Sediakan dokumentasi yang cukup untuk dipahami
- Include code examples yang berfungsi
- Jelaskan batasan dan edge cases

#### Bilingual Support
- Jika menambahkan dokumen baru, pertimbangkan untuk membuat versi English
- Ikuti struktur dari file yang sudah ada

### 6. Testing dan Validation

Sebelum membuat PR:
- Kompilasi kode tanpa warning
- Test kode di platform yang relevan
- Pastikan implementasi sesuai dokumentasi
- Verify tidak ada broken links dalam dokumentasi

### 7. Pull Request Process

#### Sebelum Submit
1. Pastikan branch Anda up-to-date dengan main branch:
   ```bash
   git fetch origin
   git rebase origin/master
   ```

2. Bersihkan commit history (jika diperlukan):
   ```bash
   git rebase -i origin/master
   ```

3. Push ke fork Anda:
   ```bash
   git push origin add/nama-teknik
   ```

#### PR Description Template
```
## Deskripsi
Penjelasan singkat tentang perubahan yang dibuat.

## Tipe Perubahan
- [ ] Teknik baru
- [ ] Perbaikan kode existing
- [ ] Dokumentasi
- [ ] Bug fix

## Teknik/Topik yang Diubah
- Sebutkan platform (Linux/Windows)
- Sebutkan kategori teknik

## Checklist
- [ ] Kode telah dikompilasi tanpa warning
- [ ] Dokumentasi sudah diupdate
- [ ] Link dalam dokumentasi sudah diverifikasi
- [ ] Tidak ada broken link
```

#### Review Process
- Tim maintainer akan melakukan review
- Mungkin ada permintaan perubahan atau klarifikasi
- Perubahan kecil bisa langsung diterima
- Perubahan besar akan didiskusikan lebih lanjut

## Lisensi

Dengan berkontribusi pada repositori ini, Anda setuju bahwa kontribusi Anda akan berlisensi di bawah lisensi yang sama dengan repositori. Pastikan kode yang Anda kontribusikan tidak melanggar hak cipta atau lisensi pihak ketiga.

## Pertanyaan atau Bantuan?

Jika Anda memiliki pertanyaan:
- Buka issue baru dengan label `question`
- Jelaskan masalah atau pertanyaan Anda dengan detail
- Berikan konteks yang cukup untuk dimengerti

## Code of Conduct

Kami mengharapkan semua kontributor untuk:
- Bersikap hormat dan profesional
- Menerima kritik konstruktif dengan baik
- Fokus pada tujuan bersama: edukasi dan keamanan

---

Terima kasih atas kontribusi Anda! 🎉
