# Shellcode Loader

Writing shellcode to allocated memory.

### Overview

Penyalinan shellcode menggunakan `RtlIpv4StringToAddress`.

Fungsi ini akan mengubah IPv4 address dari representasi string menjadi binary. IPv4 address adalah identitas host yang berperan dalam pengalamatan logis di jaringan. Ukuran sebuah IPv4 address adalah 4 byte. 

Karena IPv4 address dapat dianggap sebagai sebuah blok berukuran 4 byte, maka sebuah shellcode yang besar harus dipecah menjadi beberapa blok. Padding perlu dilakukan agar ukuran data terjaga sebagai kelipatan 4.

```c++
NTSTATUS RtlIpv4StringToAddressA (PCSTR S, BOOLEAN Strict, PCSTR * Terminator, in_addr * Addr);

NTSTATUS RtlIpv4StringToAddressW ( PCWSTR S, BOOLEAN Strict, LPCWSTR * Terminator, in_addr * Addr);

PSTR RtlIpv4AddressToStringA (const in_addr *Addr, PSTR S);

PSTR RtlIpv4AddressToStringW (const in_addr *Addr, PWSTR S);
```

### Reference

- [MSDN RtlIpv4StringToAddressA](https://docs.microsoft.com/en-us/windows/win32/api/ip2string/nf-ip2string-rtlipv4stringtoaddressa)
- [MSDN RtlIpv4StringToAddressW](https://docs.microsoft.com/en-us/windows/win32/api/ip2string/nf-ip2string-rtlipv4stringtoaddressw)
- [MSDN RtlIpv4AddressToStringA](https://docs.microsoft.com/en-us/windows/win32/api/ip2string/nf-ip2string-rtlethernetaddresstostringa)
- [MSDN RtlIpv4AddressToStringW](https://docs.microsoft.com/en-us/windows/win32/api/ip2string/nf-ip2string-rtlethernetaddresstostringw)
- [MSDN in_addr structure](https://docs.microsoft.com/en-us/windows/win32/api/winsock2/ns-winsock2-in_addr)