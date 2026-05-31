# Shellcode Loader

Access the Windows API by hash function.

### Overview

Teknik `function-hash` menyembunyikan nama API yang diakses dengan merepresentasikan target sebagai hash. 

Resolusi fungsi dilakukan dengan menelusuri setiap DLL yang telah dimuat, menghitung hash dari setiap nama fungsi dan membandingkannya dengan nilai hash target. Teknik ini menghilangkan string nama fungsi dari binary sehingga mempersulit analisis statis.

Pencarian melalui `InMemoryOrderModuleList` pada PEB dilakukan untuk mendapatkan semua module yang telah dimuat.

### Catalog

Hash function yang digunakan dapat berupa cryptographic hash ataupun non-cryptographic hash.

Daftar teknik `function-hash` yang diimplementasikan:

- [ror13](ror13): resolusi fungsi menggunakan algoritma hash ROR-13 dengan penelusuran PEB dan export table.

### References

- [PEB Structure](https://docs.microsoft.com/en-us/windows/win32/api/winternl/ns-winternl-peb)
- [PE Format — Export Directory Table](https://docs.microsoft.com/en-us/windows/win32/debug/pe-format#export-directory-table)