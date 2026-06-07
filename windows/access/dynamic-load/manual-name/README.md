# Shellcode Loader

Access the Windows API by dynamically loading.

### Overview

Resolve function dengan menelusuri daftar modul yang telah dimuat melalui PEB dan mem-parsing export table PE secara manual. Nama fungsi dibandingkan langsung dengan setiap entri di `AddressOfNames`, tanpa memanggil `GetProcAddress`, `GetModuleHandle`, atau `LoadLibrary`.

Teknik ini mendemonstrasikan apa yang dilakukan `GetProcAddress` secara internal: membaca `IMAGE_EXPORT_DIRECTORY`, menelusuri nama ekspor, dan mengambil alamat fungsi dari `AddressOfFunctions` melalui ordinal.

### How It Works

1. Baca `PEB.Ldr` dari segment register (`GS` pada x64, `FS` pada x86).
2. Iterasi `InMemoryOrderModuleList` untuk mendapatkan `DllBase` setiap modul yang dimuat. Untuk variasi resolusi lainnya, lihat [`peb-walk`](../../peb-walk).
3. Untuk setiap modul, parse header PE dan lokasi export directory.
4. Bandingkan setiap nama di `AddressOfNames` dengan nama fungsi target.
5. Jika cocok, kembalikan alamat dari `AddressOfFunctions[AddressOfNameOrdinals[i]]`.

### Advantages

- Menghindari hook EDR pada `GetProcAddress` dan API loader Win32 lainnya.
- Transparan untuk pembelajaran: menunjukkan struktur data PE dan PEB secara eksplisit.

### Disadvantages

- String nama fungsi tetap ada di binary, sehingga mudah ditemukan melalui analisis statis (gunakan [function-hash](../../function-hash) untuk menyembunyikan nama).
- Tidak menangani forwarded export atau resolusi berdasarkan ordinal (lihat [manual-ordinal](../manual-ordinal)).

### Reference

- [PEB Structure](https://docs.microsoft.com/en-us/windows/win32/api/winternl/ns-winternl-peb)
- [PE Format — Export Directory Table](https://docs.microsoft.com/en-us/windows/win32/debug/pe-format#export-directory-table)
- [MSDN GetProcAddress](https://docs.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-getprocaddress)
