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

- 32 or 64 bit register mode specificaiton
- Strict bit size adherance
- Multiple chain generations

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

## 🧪 Testing

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

## 🔖 References

- Ascii art created by [Haley Jane Wakenshaw](https://www.asciiart.eu/miscellaneous/cigarettes)