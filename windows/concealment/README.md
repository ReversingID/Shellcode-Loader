# Shellcode Loader

### Overview

Teknik `concealment` adalah teknik penyembunyian untuk mengurangi observabilitas implant selama dan setelah proses loading. Berbeda dengan kategori pipeline loading (`storage`, `writing`, `allocation`, `permission`, `execution`), teknik `concealment` berfokus pada pengaburan atau penyembunyian artifak (mengurangi jejak in-memory yang dapat dideteksi oleh scanner, EDR, atau analisi, forensik).

Kategori ini melengkapi teknik dasar loading dan sering dikombinasikan dengan kategori lain:

- **allocation / writing / permission** — menempatkan payload tanpa menciptakan region RWX mencurigakan
- **access** — resolusi API dan syscall tanpa jejak stack yang mudah dianalisis
- **execution** — timer, APC, dan mekanisme event untuk siklus sleep/wake

### Catalog

Daftar keluarga teknik `concealment` yang didokumentasikan:

- [module-stomping](module-stomping): menempatkan shellcode di dalam image modul legitim yang sudah dimuat, bukan region private executable baru.
- [sleep-obfuscation](sleep-obfuscation): mengenkripsi atau menyembunyikan memori implant selama periode idle/sleep.
- [stack-spoofing](stack-spoofing): memalsukan rantai return address agar stack unwinding terlihat seperti call path yang wajar.

### Reference

- [MITRE ATT&CK — Defense Evasion](https://attack.mitre.org/tactics/TA0005/)
- [MITRE ATT&CK — Hide Artifacts](https://attack.mitre.org/techniques/T1564/)
