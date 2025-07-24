# chainsmoker

```
                                )(/
                               (  )/
             ________________  ( /)
            ()__)____________)))))

     _         _                   _           
  __| |_  __ _(_)_ _  ____ __  ___| |_____ _ _ 
 / _| ' \/ _` | | ' \(_-< '  \/ _ \ / / -_) '_|
 \__|_||_\__,_|_|_||_/__/_|_|_\___/_\_\___|_|  

```

A rop gadget analyzer to create transfer chains between registers.

![MIT License](https://img.shields.io/badge/License-MIT-green.svg)
![Python](https://img.shields.io/badge/Python-3.10-blue.svg)

## ⚡ Features

- Multi-architecture support: x86, x64, and ARM64
- Architecture-specific register mode specification
- Strict bit size adherence
- Multiple chain generations
- Extensible architecture system for future CPUs

## 📋 Requirements

- Python 3.10 >=
- Rich
- [ropr](https://github.com/Ben-Lichtman/ropr)

## 🛠️ Installation

Create a virtual environment using your choice of venv manager.

### uv

```bash
uv venv .venv

source .venv/bin/activate # for Linux
.venv/scripts/activate # for Windows

uv pip install .
```

### venv

```bash
python -m venv .venv

source .venv/bin/activate # for Linux
.venv/scripts/activate # for Windows

pip install .
```

## 🧪 Usage

### Basic Usage

```bash
# x64 (Intel/AMD 64-bit)
chainsmoker gadgets.txt --src rax --dst rbx --arch x64

# x86 (Intel/AMD 32-bit)  
chainsmoker gadgets.txt --src eax --dst ebx --arch x86

# ARM64 (AArch64)
chainsmoker gadgets.txt --src x0 --dst x1 --arch arm64
```

### Advanced Options

```bash
# Strict mode - only use registers of exact bit width
chainsmoker gadgets.txt --src rax --dst rbx --arch x64 --strict

# Find all possible chains instead of just the first
chainsmoker gadgets.txt --src rax --dst rbx --arch x64 --all

# Increase search depth (default: 5)
chainsmoker gadgets.txt --src rax --dst rbx --arch x64 --depth 10

# Verbose output for debugging
chainsmoker gadgets.txt --src rax --dst rbx --arch x64 --verbose
```

### Supported Registers

#### x86 (32-bit)
- General purpose: `eax`, `ebx`, `ecx`, `edx`, `esi`, `edi`, `esp`, `ebp`

#### x64 (64-bit)  
- General purpose: `rax`, `rbx`, `rcx`, `rdx`, `rsi`, `rdi`, `rsp`, `rbp`
- Extended: `r8`, `r9`, `r10`, `r11`, `r12`, `r13`, `r14`, `r15`
- 32-bit variants: `eax`, `ebx`, `ecx`, `edx`, `esi`, `edi`, `r8d`-`r15d`

#### ARM64 (AArch64)
- 64-bit: `x0`-`x30`, `sp`, `lr`, `xzr`
- 32-bit variants: `w0`-`w30`, `wsp`, `wzr`

## 🧪 Development

```bash
hatch shell

python -m chainsmoker
```

To remove previous environments, run

```bash
hatch env prune
```

## 🚧 TODO

- Add "do not touch these registers"
- Add RISC-V architecture support
- Add MIPS architecture support
- Auto-detect architecture from gadget file format

## 🔖 References

- Ascii art created by [Haley Jane Wakenshaw](https://www.asciiart.eu/miscellaneous/cigarettes)