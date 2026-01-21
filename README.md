# TinyPEParser

## What is it?

This is a small project that I did for fun that parses PE files and prints out important PE structures such as imports or exports, etc..

## How to use it?

Simply pass in the path to your PE image as a command line argument.

```batch
TinyPEParser.exe <file>
```

## Checklist

- [x] Import Parsing

- [ ] Export Parsing

- [ ] Entry Points and TLS callbacks

- [ ] Relocation Table

- [ ] Generic Header Information (MZ Header, PE Header and Section Headers)
