# machscope

Mach-O and DWARF inspection in pure MoonBit.

`machscope` reads Apple's executable format without an Apple toolchain on the
machine doing the reading. That matters in two places: CI running on Linux
cannot invoke `otool`, `codesign` or `atos`; and a browser cannot invoke
anything. Both can run MoonBit, so both can parse a binary directly.

## What it does today

| Capability | Status |
|---|---|
| Thin Mach-O, 32/64-bit, both byte orders | done |
| Universal (fat) binaries, `fat_arch` and `fat_arch_64` | done |
| Load-command framing with full bounds checking | done |
| Type-level `cpusubtype` / capability-bit split | done |
| Segment and section table, address ↔ file offset | done |
| Symbol table with names resolved through the string table | done |
| Embedded code signature: superblob, CodeDirectory | done |
| Entitlements, reached through the PKCS#7 DER wrapper | done |
| DWARF 5 line tables, address → `file:line:column` | done |
| CLI (`header`, `--commands`, `--symbols`, `--sections`, `--signature`, `--lookup`) | done |
| dyld export trie, chained fixups | planned |
| `.debug_info` variable and type lookup | planned |

## Why it is written this way

Every field read goes through a bounds-checked cursor. A truncated or corrupt
file produces a typed `MachscopeError` naming the field and the offset that
failed, never an out-of-range read and never a partially-parsed structure
reported as success. Lengths taken from the file are checked before they are
used to allocate or iterate.

The parser is two-stage on purpose: `parse_slice` validates the header and walks
the load-command table end to end, and only then are individual commands
interpreted. A file whose command table does not tile `sizeofcmds` exactly is
rejected before any command-specific code runs.

## Symbolicating a crash address

The end-to-end case, checked against `dwarfdump` on the fixture:

```
$ machscope 0x100000490 internal/fixtures/sample.dsym
t.c:3:33
```

`dwarfdump --debug-line` reports the same address as line 3, column 33. The
path is assembled from the line program's directory table and file table, both
of which DWARF 5 encodes as a description of forms rather than as plain strings.

## Usage

```moonbit nocheck
let file = @machscope.parse(bytes)
match file {
  Thin(slice) => {
    println(slice.header.kind)           // MH_MAGIC_64
    println(slice.header.cpu_type)       // 16777228 (arm64)
    println(slice.header.cpu_subtype_base())
    println(slice.header.cpu_capabilities()) // 0x80 for arm64e
    for cmd in slice.commands {
      println(cmd.cmd)                   // e.g. LC_SEGMENT_64
    }
  }
  Fat(slices) => {
    for slice in slices {
      println("\{slice.cpu_type} @ \{slice.offset}+ \{slice.size}")
    }
  }
}
```

## Testing

```sh
moon test
```

Three layers, each catching what the others cannot:

1. **Synthetic buffers** built byte by byte pin down each rejection rule. No
   real linker emits a header with an unaligned `cmdsize`, so these cases can
   only be constructed.
2. **Real fixtures** under `internal/fixtures/` are `/bin/ls` from macOS 15,
   both as the original universal binary and thinned per architecture with
   `lipo`.
3. **Differential tests against `otool`** — `oracle_wbtest.mbt` asserts values
   copied from `otool -h` and `otool -f` on those same fixtures. A parser
   agreeing with itself proves nothing; agreeing with the tool Apple ships
   proves something.

## Licence

Apache-2.0. The fixture binaries are Apple system binaries used only as test
inputs and are not redistributed as part of the library's functionality; see
`internal/fixtures/README.md`.