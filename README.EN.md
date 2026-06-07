# Shellcode Loader

Open repository for learning dynamic shellcode loading.

**Language:** [Bahasa Indonesia](README.md) | English

---

## Introduction

This repository collects information about techniques for loading shellcode into memory, which are commonly used by implants. This repository is open for public access and can be accessed by anyone from both within and outside the `Reversing.ID` community.

### What is Shellcode?

`Shellcode` is a piece of code/instructions carefully crafted to execute a specific action. In exploitation, shellcode is used as a payload to be injected into a system with certain constraints.

In theory, shellcode can do anything. Originally, shellcode was just a list of instructions that would spawn a shell. Since then, shellcode has evolved and can perform various actions such as creating a user, deleting data, etc.

**Example shellcode used in samples:**
```
# 9090CCC3

0000:  90      nop
0001:  90      nop
0002:  CC      int3
0003:  c3      ret
```

---

## Basic Techniques

This repository covers the basic processes in shellcode loading:

| Technique | Description |
|-----------|-------------|
| **allocation** | Strategy for allocating memory to hold shellcode as executable code |
| **storage** | Strategy for storing shellcode before execution |
| **execution** | Strategy for executing shellcode from memory |
| **writing** | Strategy for writing/modifying code to memory, either directly or through transformation |
| **permission** | Management of memory permission/attributes to allow execution |
| **access** | System APIs used in the loading process (especially Windows) |

Some techniques utilize APIs provided by the OS, either directly or indirectly.

---

## Repository Structure

```
Shellcode-Loader/
├── linux/                  # Techniques for Linux
│   ├── allocation/        # Memory allocation
│   ├── storage/          # Shellcode storage
│   ├── execution/        # Code execution
│   ├── writing/          # Code writing
│   └── permission/       # Permission management
│
├── windows/              # Techniques for Windows
│   ├── access/           # Windows API reference
│   ├── allocation/       # Memory allocation
│   ├── storage/          # Shellcode storage
│   ├── execution/        # Code execution (with sub-techniques)
│   │   ├── asm-jmp/
│   │   ├── callback/
│   │   ├── event/
│   │   ├── fiber/
│   │   ├── invoke/
│   │   └── thread/
│   ├── writing/          # Code writing
│   └── permission/       # Permission management
│
├── README.md             # Documentation (Bahasa Indonesia)
├── README.EN.md          # Documentation (English)
├── CONTRIBUTING.md       # Contribution guide
├── RESOURCES.md          # Complete index and references
└── .gitignore           # Git ignore rules
```

---

## Quick Start

### 1. Start Here
- **New here?** Read the [Introduction](#what-is-shellcode) above
- **Want to see all techniques?** Check out [RESOURCES.md](RESOURCES.md)
- **Want to contribute?** Read [CONTRIBUTING.EN.md](CONTRIBUTING.EN.md)

### 2. Choose Your Platform
- **Linux:** Open the [linux/](linux/) directory
- **Windows:** Open the [windows/](windows/) directory

### 3. Select a Technique
Each technique directory contains:
- `README.md` - Technique documentation
- Directory (e.g. `c++/`) containing implementation code in specific language
- Examples and explanations

---

## Notes

- Techniques in this repository focus on x86 (and also x64) architecture, unless stated otherwise
- Documentation and implementations are primarily in Bahasa Indonesia with English versions available
- This repository is an open educational resource for the cybersecurity community

---

## Contributing

We welcome contributions from the community! For a complete guide on how to contribute:
- Read [CONTRIBUTING.EN.md](CONTRIBUTING.EN.md) (English)
- Read [CONTRIBUTING.md](CONTRIBUTING.md) (Bahasa Indonesia)

---

## Disclaimer

This repository is intended for educational purposes and legitimate cybersecurity research. All techniques and code in this repository are for learning and authorized security investigations. Users are responsible for how they use the information in this repository and must comply with all applicable laws and regulations in their jurisdiction.