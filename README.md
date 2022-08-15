# Rrop
Find gadgets and generate rop chain for Elf64 binaries.

## Disclaimer
I started this project to learn the Rust language.

## How to use

Find gadgets
```
Rrop binary.elf
```

Generate a ropchain
```
Rrop binary.elf --binsh --pwntool --writable-address 4980736 -o exploit.py
```