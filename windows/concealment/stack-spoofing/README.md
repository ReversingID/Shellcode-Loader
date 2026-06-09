# Shellcode Loader

Memalsukan rantai return address agar stack unwinding terlihat legitim.

### Overview

Teknik `stack-spoofing` memanipulasi call stack sehingga unwinder (EDR, ETW stack walk, debugger) melihat rantai return address yang wajar — biasanya menunjuk ke fungsi di dalam `ntdll.dll`, `kernel32.dll`, atau DLL sistem lainnya. Teknik ini sering dipasangkan dengan indirect syscall dan API sensitif untuk menyembunyikan asal panggilan yang sebenarnya.

### Related

- [access/syscalls](../../access/syscalls): indirect syscall dan gate (`hells-gate`, `recycled-gate`, dll.).
- [access/dynamic-load](../../access/dynamic-load): resolusi gadget dan fungsi di DLL legitim.
- [execution](../../execution): primitif eksekusi yang dibungkus dengan stack spoof.
