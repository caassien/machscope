# machscope

Mach-O and DWARF inspection in pure MoonBit.

Reads Apple's executable format with no Apple toolchain present. Linux CI
cannot run `otool`, `codesign` or `atos`, and a browser cannot run them either;
both can run MoonBit.

## Quick start

```sh
moon run cmd/main -- internal/fixtures/sample.bin
```

```
internal/fixtures/sample.bin:
  header      arm64 MH_MAGIC_64 (little-endian), subtype 0, filetype 2, 17 commands, 1056 bytes
  cpu         type 16777228, subtype 0, capabilities 0x0
  filetype    2
  flags       0x200085
```

The segment table, verified field by field against `otool -l`:

```
$ moon run cmd/main -- --sections internal/fixtures/sample.bin
  __PAGEZERO  vmaddr 0x0  vmsize 0x100000000  fileoff 0  filesize 0
  __TEXT  vmaddr 0x100000000  vmsize 0x4000  fileoff 0  filesize 16384
    __text  addr 0x100000460  size 200  offset 1120
    __stubs  addr 0x100000528  size 12  offset 1320
  __DATA_CONST  vmaddr 0x100004000  vmsize 0x4000  fileoff 16384  filesize 16384
    __got  addr 0x100004000  size 8  offset 16384
```

The code signature identity, matching `codesign -dvv`:

```
$ moon run cmd/main -- --signature internal/fixtures/sample.bin
  identifier  sample.arm64
  version     0x20400
  flags       0x20002
  hash        2
  slots       9
```

This is a structural read, not a verification: see [Code signature](#code-signature)
below for what the library does and does not claim about a signature.

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
| Entitlements from slot 5 (XML) and slot 7 (DER plist) | done |
| DWARF 5 line tables, address → `file:line:column` | done |
| CLI: `header`, `--commands`, `--symbols`, `--sections`, `--signature`, `--exports`, `--fixups`, `--lookup` | done |
| `--json` output for every mode | done |
| dyld export trie | done |
| Chained fixups: `PTR_64`, `PTR_64_OFFSET`, arm64e authenticated | done |
| Classic `LC_DYLD_INFO` rebase/bind opcode streams | done |
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
plist.mbt          Apple's DER property-list encoding, as used by slot 7
der.mbt            ASN.1 framing: tags, lengths, children
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

## Code signature

`machscope` reads a signature; it does not verify one. There is no page-hash
recomputation, no CMS signature check, no certificate chain walk and no
Gatekeeper policy. `LC_CODE_SIGNATURE` names a byte range, the range holds a
`SuperBlob`, and this library decodes the blobs in it:

| Slot | Magic | Contents |
|---|---|---|
| `0` | `0xfade0c02` | CodeDirectory: identifier, team id, version, flags, hash type, slot counts |
| `5` | `0xfade7171` | Entitlements, as plist XML |
| `7` | `0xfade7172` | Entitlements, as Apple's DER property list |
| `0x10000` | `0xfade0b01` | CMS signature *over* the CodeDirectory — no entitlements |

The distinction between slot 7 and `0x10000` is the one worth stating plainly,
because the CMS blob is the obvious place to look for entitlements and the wrong
one: it is a signature, and walking it for an `OCTET STRING` returns signature
bytes. Only slots 5 and 7 carry the entitlements dictionary. A binary may carry
either, both, or neither.

The "checking" the library does is structural, and the rules are specific: the
declared signature range must lie inside the file, a `SuperBlob` may not claim
more bytes than that range, and every indexed blob must be able to supply its
own eight-byte header. A file violating any of these is rejected with the field
and offset that failed. Whether the signature is *valid* is not a question this
library answers.

```
$ moon run cmd/main -- --entitlements /usr/bin/ssh
{"com.apple.private.amfi.version-restriction":1,
 "keychain-access-groups":["com.apple.ssh.passphrases"]}
```

`codesign -d --entitlements :- /usr/bin/ssh` prints the same two keys. The DER
decoder also handles the nested dictionaries and arrays a signed application
carries: `Finder.app` has over a hundred keys, some of them dicts of dicts.

## Symbolicating a crash address

Checked against `dwarfdump` on the fixture:

```
$ machscope 0x100000490 internal/fixtures/sample.dsym
sample.c:12:21
```

`dwarfdump --debug-line` reports the same address as line 12, column 21. The
path comes from the line program's directory and file tables, which DWARF 5
encodes as form descriptions rather than plain strings.

## Chained fixups

Modern binaries put each rebase and bind in the slot it patches, with the
distance to the next slot packed alongside. Both the plain 64-bit formats and
the arm64e authenticated ones are decoded; the latter carry a signing key, a
diversity value and an address discriminator in the bits the plain format uses
for the import ordinal.

```
$ machscope --fixups internal/fixtures/sample.chains
internal/fixtures/sample.chains: 65 fixups
  0x100004000 bind _printf (lib 1)
  0x100008000 rebase -> 0xb4d
  ...
```

All 65 addresses and types match `dyld_info -fixups` on that file: one bind in
`__DATA_CONST,__got` and 64 rebases chained through `__DATA,__data`. The 64
rebases matter — a chain of length one never reads the `next` field, so a single
fixup cannot tell a correct walk from a broken one. That is how a stride bug
once shipped: `next` was read from the low bits of `target` instead of bit 51,
and `/usr/bin/ssh` reported 12 fixups where `dyld_info` reported 1024.

Images linked before chained fixups describe the same relocations with two
opcode streams named by `LC_DYLD_INFO_ONLY`, and x86_64 slices of universal
binaries still do. Both encodings decode into the same `Fixup`:

```
$ machscope --fixups internal/fixtures/sample.classic
internal/fixtures/sample.classic: 6 fixups
  0x100002000 rebase -> 0x10000061c
  ...
  0x100001000 bind dyld_stub_binder (lib 1)
  0x100002000 lazy-bind _printf (lib 1)
```

The lazy bind is labelled apart from the plain bind on purpose: dyld does not
resolve that slot at launch, and a caller asking what the loader does before
`main` runs needs the difference.

Against all 967 Mach-O files in `/bin`, `/usr/bin`, `/usr/sbin` and `/sbin`,
every address and type agrees with `dyld_info -fixups`.

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
sample.fat             parse (header+commands)      5.2 us
sample.fat             segments, both slices       16.4 us
sample.chains          parse (header+commands)      2.4 us
sample.chains          chained fixups, 65 slots    22.0 us
sample.fat             exports, both slices        13.8 us
sample.dsym            line tables                 37.4 us
sample.dsym            address lookup              38.0 us
```

Parsing is linear in file size. The 65-slot chain walk dominates its file: each
slot is one bounds-checked read plus a decode, and the walk cannot batch them
because every slot names where the next one is.

## Testing

```sh
moon test
```

Three layers:

1. **Synthetic buffers** pin down each rejection rule and each format variant.
   No real linker emits an unaligned `cmdsize` or a big-endian PowerPC image,
   so those cases have to be constructed.
2. **Fixtures** in `internal/fixtures/`, all generated from `sample.c`,
   `chains.c`, `classic.c` and `entitled.c` by `make_fixtures.sh`: a universal
   binary, its slices, an arm64e build, a chain long enough to walk, one image
   using the pre-chained-fixup `LC_DYLD_INFO` encoding, a DWARF 5 dSYM, a
   DWARF 4 dSYM, and the two entitlement payloads `codesign` wrote.
3. **Differential tests** assert values copied from `otool -h`, `otool -f`,
   `otool -l`, `nm`, `codesign -dvv`, `dyld_info -exports`, `dyld_info -fixups`
   and `dwarfdump --debug-line` run on those same fixtures.

The suite is 133 tests, 35 of them differential. `moon test --enable-coverage`
plus `moon coverage analyze` reports what is not exercised; the remaining gaps
are mostly error branches for malformed inputs that no fixture can reach.

## Licence

Apache-2.0, copyright 2026 刁礼财 (caassien). Every binary in
`internal/fixtures/` is generated from source in this repository by
`internal/fixtures/make_fixtures.sh`; none of them is a third-party binary. See
`internal/fixtures/README.md` for the provenance of each file and why they are
generated rather than committed.