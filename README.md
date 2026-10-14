# elflens

Static binary format auditor for ELF, PE, and Mach-O. Parses file structure and reports. It never executes, patches, injects into, or modifies its input.

## Build

```
make
```

C11, no dependencies beyond libm. Produces `./elflens`.

## Usage

```
elflens [options] <file>
  -j, --json      emit JSON
  -s, --strings N print strings of minimum length N
  -l, --libs      print linked libraries only
  -h, --help
  -V, --version
```

## Reports

- format, endianness, bit width, entry point
- section table with per-section size and Shannon entropy
- whole-file entropy, which surfaces packing or encryption
- linked libraries from `DT_NEEDED`
- symbol table presence and stripped status
- GNU build ID
- dynamic loader path
- hardening: NX, PIE, stack canary, RELRO, with a letter grade
- SHA-256, SHA-1, MD5 of the file

## Examples

```
./elflens /bin/bash
./elflens -j /bin/bash | jq .hardening
./elflens -l ./elflens
./elflens -s 10 somefile
```

## Hardening detection

NX and RELRO come from the dynamic section, PIE from ELF type, stack canary from the presence of `__stack_chk_fail` in the symbol table. Static binaries correctly report no interpreter.

## Safety

Input is bounds-checked before parsing. A malformed or truncated file is rejected rather than trusted. Verified clean under ASAN and UBSAN against truncated and random inputs.

## License

Apache-2.0
