# Shellcode Loader

Writing shellcode to allocated memory.

### Overview

Penyalinan shellcode menggunakan `RtlEthernetStringToAddress`.

Fungsi ini akan mengubah MAC address dari representasi string menjadi binary. MAC address adalah identitas unik sebuah `Network Interface Controller (NIC)` dengan ukuran tetap 6 byte. 

Karena MAC address dapat dianggap sebagai sebuah blok berukuran 6 byt, maka sebuah shellcode yang besar harus dipecah menjadi beberapa MAC address. Padding perlu dilakukan agar ukuran data terjaga sebagai kelipatan 6.

```c++
NTSTATUS RtlEthernetStringToAddressA (PCSTR S, PCSTR * Terminator, DL_EUI48 * Addr);

NTSTATUS RtlEthernetStringToAddressW ( PCWSTR S, LPCWSTR * Terminator, DL_EUI48 * Addr);

PSTR RtlEthernetAddressToStringA (const DL_EUI48 *Addr, PSTR S);

PSTR RtlEthernetAddressToStringW (const DL_EUI48 *Addr, PWSTR S);
```

### Reference

- [MSDN RtlEthernetStringToAddressA](https://docs.microsoft.com/en-us/windows/win32/api/ip2string/nf-ip2string-rtlethernetstringtoaddressa)
- [MSDN RtlEthernetStringToAddressW](https://docs.microsoft.com/en-us/windows/win32/api/ip2string/nf-ip2string-rtlethernetstringtoaddressw)
- [MSDN RtlEthernetAddressToStringA](https://docs.microsoft.com/en-us/windows/win32/api/ip2string/nf-ip2string-rtlethernetaddresstostringa)
- [MSDN RtlEthernetAddressToStringW](https://docs.microsoft.com/en-us/windows/win32/api/ip2string/nf-ip2string-rtlethernetaddresstostringw)