# Shellcode Loader

Writing shellcode to allocated memory.

### Overview

Penyalinan shellcode menggunakan `RtlIpv6StringToAddress`.

Fungsi ini akan mengubah IPv6 address dari representasi string menjadi binary. IPv6 address adalah identitas host yang berperan dalam pengalamatan logis di jaringan. Ukuran sebuah IPv6 address adalah 16 byte. 

Karena IPv6 address dapat dianggap sebagai sebuah blok berukuran 16 byte, maka sebuah shellcode yang besar harus dipecah menjadi beberapa MAC address. Padding perlu dilakukan agar ukuran data terjaga sebagai kelipatan 16.

```c++
NTSTATUS RtlIpv6StringToAddressA (PCSTR S, PCSTR * Terminator, in6_addr * Addr);

NTSTATUS RtlIpv6StringToAddressW ( PCWSTR S, LPCWSTR * Terminator, in6_addr * Addr);

PSTR RtlIpv6AddressToStringA (const in6_addr *Addr, PSTR S);

PSTR RtlIpv6AddressToStringW (const in6_addr *Addr, PWSTR S);
```

### Reference

- [MSDN RtlIpv6StringToAddressA](https://docs.microsoft.com/en-us/windows/win32/api/ip2string/nf-ip2string-rtlipv6stringtoaddressa)
- [MSDN RtlIpv6StringToAddressW](https://docs.microsoft.com/en-us/windows/win32/api/ip2string/nf-ip2string-rtlipv6stringtoaddressw)
- [MSDN RtlIpv6AddressToStringA](https://docs.microsoft.com/en-us/windows/win32/api/ip2string/nf-ip2string-rtlethernetaddresstostringa)
- [MSDN RtlIpv6AddressToStringW](https://docs.microsoft.com/en-us/windows/win32/api/ip2string/nf-ip2string-rtlethernetaddresstostringw)