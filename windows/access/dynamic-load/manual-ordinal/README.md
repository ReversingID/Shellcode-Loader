# Shellcode Loader

Access the Windows API by dynamically loading.

### Overview

Resolve function dengan menelusuri PEB, mencocokkan `BaseDllName` modul target (misal `kernel32.dll`), lalu mengambil alamat ekspor dari `AddressOfFunctions` berdasarkan ordinal — tanpa `GetProcAddress`, `GetModuleHandle`, atau `LoadLibrary`.

Resolusi terdiri atas dua langkah, analog dengan `GetModuleHandle` + `GetProcAddress`:

- `resolve_module(target_dll)` — cari `DllBase` dari PEB berdasarkan `BaseDllName`.
- `resolve_ordinal(base, ordinal)` — indeks `AddressOfFunctions` berdasarkan ordinal ekspor.

### How It Works

1. `resolve_module`: baca `PEB.Ldr`, iterasi `InMemoryOrderModuleList` hingga `BaseDllName` cocok. Untuk variasi resolusi lainnya, lihat [`module-enumeration`](../../module-enumeration/).
2. `resolve_ordinal`: parse `IMAGE_EXPORT_DIRECTORY` dari `DllBase`.
3. Hitung indeks: `index = ordinal - exp->Base`.
4. Kembalikan `image + AddressOfFunctions[index]`.

`resolve_func_by_ordinal` tersedia sebagai wrapper yang menggabungkan kedua langkah di atas.

### Obtaining Ordinals

Ordinal ekspor bergantung pada versi dan build Windows. Dapatkan nilai yang benar dengan:

```sh
dumpbin /exports C:\Windows\System32\kernel32.dll
```

Contoh baris output:

```
    ordinal hint RVA      name
       1273  4F8 00015540 VirtualAlloc
```

Gunakan kolom **ordinal** (bukan hint). Sample di repo mereferensikan Windows 7 SP1 x64 (`6.1.7600`); perbarui konstanta di `code.cpp` untuk lingkungan target Anda.

### Advantages

- Menghindari hook EDR pada `GetProcAddress` dan API loader Win32 lainnya.
- Tidak ada string nama fungsi pada panggilan resolver (hanya nama DLL dan nilai ordinal).

### Disadvantages

- Ordinal **spesifik versi** — harus dicari ulang per target `kernel32.dll` (atau DLL lain).
- String nama DLL tetap ada di binary.
- Tidak menangani forwarded export.

### Reference

- [PEB Structure](https://docs.microsoft.com/en-us/windows/win32/api/winternl/ns-winternl-peb)
- [PE Format — Export Directory Table](https://docs.microsoft.com/en-us/windows/win32/debug/pe-format#export-directory-table)
- [MSDN GetProcAddress](https://docs.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-getprocaddress)
