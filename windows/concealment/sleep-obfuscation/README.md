# Shellcode Loader

Mengenkripsi atau menyembunyikan memori implant selama periode idle.

### Overview

Teknik `sleep-obfuscation` teknik melindungi artefak in-memory implant selama periode tidak aktif (beacon sleep, `Sleep`, atau timer interval). Payload dan data sensitif dienkripsi, diubah permission-nya, atau disembunyikan sehingga memory scanner yang berjalan saat implant idle melihat konten yang tidak mencurigakan.

### Related

- [execution/event](../../execution/event): timer, APC, dan mekanisme wake.
- [permission](../../permission): perubahan atribut halaman selama siklus sleep.
- [writing/encryption](../../writing/encryption): primitif enkripsi untuk masking memori.
