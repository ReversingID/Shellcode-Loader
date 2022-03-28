# Shellcode Loader

Open repository for learning dynamic shellcode loading.

### Disclaimer

This repository is used to collect information related to loading shellcode into memory which usually used by implants. This repository is open for public, publicly accessible to anyone.

### Content

The codes are classified into several categories based on platform (OS) and techniques. Each directory refer to specific technique and contain brief introduction as well as simple implementation in certain programming language (mostly in C/C++).

Note: the techniques will focus on x86 architecture, unless told otherwise.

### Shellcode Overview

`Shellcode` is a piece of code/instructions which carefully crafted to execute specific action. In exploitation, shellcode is used as payload which will be injected to system (or application).

Theoretically, shellcode can do anything. In early time, shellcode is just list of instructions which will spawn a shell. Then, shellcode evolve and has various actions such as create user, delete data, etc.

For collection of shellcodes, go to [shellcodes repository](https://github.com/ReversingID/shellcodes).

For collection of process injection techniques, go to [injection repository](https://github.com/ReversingID/injection).

For simplicity, shellcode used in the sample will be:

```
# 9090CCC3

0000:  90      nop
0001:  90      nop
0002:  CC      in3
0003:  c3      ret
```

### Techniques

This repository will cover basic process in shellcode loading:
- `allocation`: how to allocate memory to store shellcode temporary (as code).
- `storage`: how to store shellcode.
- `execution`: how to execute shellcode.
- `writing`: how to write code to memory (self), either directly copy or using any transformation.

Some techniques use API provided by the OS, directly or indirectly.