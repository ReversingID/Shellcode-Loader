# Shellcode Loader

Executing shellcode as a thread.

### Overview

Thread Local Storage (TLS) callback dipanggil sebelum eksekusi entrypoint terjadi. Beberapa trik anti-debug dan anti-vm umum dilakukan sebagai TLS callback karena berada pada flow yang berbeda dengan entrypoint.

Jumlah TLS callback dapat lebih dari satu dan terkadang di dalam satu callback dapat dibuat callback lain saat runtime.