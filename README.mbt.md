# machscope

Mach-O and DWARF inspection in pure MoonBit.

Reads Apple's executable format with no Apple toolchain present. Linux CI
cannot run `otool`, `codesign` or `atos`, and a browser cannot run them either;
both can run MoonBit.

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
| CLI: `header`, `--commands`, `--symbols`, `--sections`, `--signature`, `--lookup` | done |
| dyld export trie | done |
| Chained fixups, rebase/bind opcodes | planned |
| `.debug_info` variable and type lookup | planned |

## Design notes

Every field read goes through a bounds-checked cursor. A corrupt file yields a
typed `MachscopeError` naming the field and offset that failed; it never yields
an out-of-range read or a partially-parsed result. Lengths from the file are
checked before they are used to allocate or iterate.

Parsing is two-stage: `parse_slice` walks the whole load-command table, and only
then are commands interpreted. A command table that does not tile `sizeofcmds`
is rejected before any command-specific code runs.

## Symbolicating a crash address

Checked against `dwarfdump` on the fixture:

```
$ machscope 0x100000490 internal/fixtures/sample.dsym
t.c:3:33
```

`dwarfdump --debug-line` reports the same address as line 3, column 33. The
path comes from the line program's directory and file tables, which DWARF 5
encodes as form descriptions rather than plain strings.

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

Three layers:

1. **Synthetic buffers** pin down each rejection rule. No real linker emits an
   unaligned `cmdsize`, so these cases have to be constructed.
2. **Real fixtures** in `internal/fixtures/`: `/bin/ls` from macOS 15 (universal
   and thinned per architecture), a dSYM built from `sample.c`, and that
   binary.
3. **Differential tests** assert values copied from `otool -h`, `otool -f`,
   `nm`, `codesign -dvv`, `dyld_info -exports` and `dwarfdump --debug-line` for
   those same fixtures.

## Licence

Apache-2.0. The fixture binaries are Apple system binaries used only as test
inputs and are not redistributed as part of the library's functionality; see
`internal/fixtures/README.md`.