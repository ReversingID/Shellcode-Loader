# Shellcode Loader

### Overview

Eksekusi shellcode sebagai thread terpisah dengan shared memory address (berbagi ruang memory antar thread dalam satu process). Terdapat beberapa fungsi Threading di Windows (public/internal) yang dapat dimanfaatkan untuk menjalankan thread.

Secara garis besar, shellcode yang telah diekstrak akan disalin ke ruang memory yang telah dialokasikan. Alamat shellcode kemudian menjadi fungsi entrypoint bagi thread.

Variasi dikelompokkan berdasarkan asal API: Win32 publik, native/undocumented, thread pool, Shell API, dan callback loader.

### Catalog

**API Win32 publik**

- [CreateThread](CreateThread): buat thread baru; shellcode sebagai `LPTHREAD_START_ROUTINE`.
- [CreateRemoteThread](CreateRemoteThread): varian remote thread; dapat dipakai pada proses sendiri via `GetCurrentProcess()`.
- [CreateRemoteThreadEx](CreateRemoteThreadEx): varian extended dengan atribut thread dan pengembalian thread ID.

**Native / undocumented**

- [NtCreateThreadEx](NtCreateThreadEx): pembuatan thread via syscall native `NtCreateThreadEx`.
- [RtlCreateUserThread](RtlCreateUserThread): pembuatan thread user-mode melalui ntdll.
- [EtwpCreateEtwThread](EtwpCreateEtwThread): pembuatan thread internal ETW di ntdll (undocumented).

**Thread pool**

- [CreateThreadpoolWork](CreateThreadpoolWork): submit shellcode sebagai work item thread pool.
- [TrySubmitThreadpoolCallback](TrySubmitThreadpoolCallback): kirim callback sederhana ke thread pool tanpa objek work persisten.
- [TpSimpleTryPost](TpSimpleTryPost): varian internal ntdll untuk posting callback ke thread pool (undocumented).

**Shell API**

- [SHCreateThread](SHCreateThread): pembuatan thread via Shell helper `SHCreateThread`.
- [SHCreateThreadWithHandle](SHCreateThreadWithHandle): varian yang mengembalikan handle thread.

**Callback loader**

- [tls-callback](tls-callback): eksekusi shellcode sebagai TLS callback sebelum entry point utama dijalankan.
