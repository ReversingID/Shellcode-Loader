# Shellcode Loader

Executing shellcode by raising signal (with sigaction).

### Overview

Daftarkan shellcode ke sebuah signal tertentu dengan `sigaction` dan eksekusi dengan memicu signal yang sesuai.

Gunakan signal yang umum terjadi seperti: SIGUSR1, SIGUSR2, SIGCHLD. Hindari memicu signal mencurigakan seperti SIGSEGV, SIGILL, dsb.

```c++
#include <signal.h>

int sigaction(int signum, const struct sigaction *act, struct sigaction * oldact);
```

### Reference

- [Man 2](https://man7.org/linux/man-pages/man2/sigaction.2.html)