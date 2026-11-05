# machscope

Mach-O and DWARF inspection in pure MoonBit.

Reads Apple's executable format with no Apple toolchain present. Linux CI
cannot run `otool`, `codesign` or `atos`, and a browser cannot run them either;
both can run MoonBit.

## Quick start

```sh
moon run cmd/main -- internal/fixtures/ls.x86_64.macho
```

```
arch x86_64:
  header      x86_64 MH_MAGIC_64 (little-endian), subtype 3, filetype 2, 18 commands, 1736 bytes
  cpu         type 16777223, subtype 3, capabilities 0x0
  filetype    2
  flags       0x200085
```

The segment table, verified field by field against `otool -l`:

```
$ moon run cmd/main -- --sections internal/fixtures/ls.x86_64.macho
  __PAGEZERO  vmaddr 0x0  vmsize 0x100000000  fileoff 0  filesize 0
  __TEXT  vmaddr 0x100000000  vmsize 0x5000  fileoff 0  filesize 20480
    __text  addr 0x100000718  size 15095  offset 1816
    __stubs  addr 0x10000420f  size 504  offset 16911
```

The code signature identity, matching `codesign -dvv`:

```
$ moon run cmd/main -- --signature internal/fixtures/ls.x86_64.macho
  identifier  com.apple.ls
  version     0x20400
  flags       0x0
  hash        2
  slots       8
```

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
| CLI: `header`, `--commands`, `--symbols`, `--sections`, `--signature`, `--exports`, `--fixups`, `--lookup` | done |
| `--json` output for every mode | done |
| dyld export trie | done |
| Chained fixups: `PTR_64`, `PTR_64_OFFSET`, arm64e authenticated | done |
| `.debug_info` variable and type lookup | planned |

## How it is laid out

```
machscope.mbt      errors, byte order, the cursor type
reader.mbt         bounds-checked reads of every primitive
macho.mbt          magic numbers, fat tables, mach_header, command framing
commands.mbt       LC_SYMTAB and the symbol table
segments.mbt       LC_SEGMENT_64, sections, address ↔ offset
exports.mbt        dyld export trie
fixups.mbt         chained fixups: imports, segment chains, rebase/bind
signature.mbt      superblob index, CodeDirectory, entitlements
der.mbt            the DER subset needed to reach a plist
dwarf.mbt          line program prologues, LEB128
dwarf_line.mbt     the line-number state machine, address lookup
json_report.mbt    Json values for every structure
cmd/main/          the CLI
bench/             timing harness
```

`reader.mbt` is the only file that indexes a buffer. Everything above it works
through `Bounds` and `Cursor`, which is what keeps a malformed length from
turning into an out-of-range read anywhere else.

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

## Chained fixups

Modern binaries put each rebase and bind in the slot it patches, with the
distance to the next slot packed alongside. Both the plain 64-bit formats and
the arm64e authenticated ones are decoded; the latter carry a signing key, a
diversity value and an address discriminator in the bits the plain format uses
for the import ordinal.

```
$ machscope --fixups internal/fixtures/ls.arm64e.macho
internal/fixtures/ls.arm64e.macho: 113 fixups
  0x100008000 bind _humanize_number (lib 1)
  0x100008008 bind _tgetent (lib 2)
  ...
```

All 113 addresses match `dyld_info -fixups` on that file.

## JSON output

`--json` is accepted with any mode; the report always carries the header and
the command table, and adds segments, symbols or exports when the corresponding
flag is present. Thin and universal files produce the same shape, with the
slice's placement in the file as extra `fat_*` keys.

```
$ machscope --json --exports sample.bin
{
  "architectures": [
    {
      "header": { "magic": "MH_MAGIC_64", ... },
      "commands": [ ... ],
      "exports": [
        { "name": "_main", "offset": "0x478", "flags": 0, "weak": false,
          "reexport": false }
      ]
    }
  ]
}
```

Addresses are hex strings rather than JSON numbers: a 64-bit address does not
survive a round trip through a double.

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

## Performance

`moon run bench`, on an M-series Mac, mean of 50 runs:

```
fixture                operation                    mean
ls.x86_64.macho        parse (header+commands)      2.7 us
ls.x86_64.macho        segments                    14.7 us
ls.x86_64.macho        symbols                     47.6 us
ls.fat.macho           parse both slices            6.4 us
ls.fat.macho           exports, both slices        10.3 us
sample.dsym            line tables                 39.9 us
sample.dsym            address lookup              40.1 us
```

Parsing is linear in file size. The symbol table dominates the thin file
because it resolves 93 names through the string table; everything else is a
single pass over its own section.

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