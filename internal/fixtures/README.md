# Test fixtures

Every fixture here is generated from source in this directory by
`make_fixtures.sh`, using the Xcode command line tools. None of them are
third-party binaries.

They are inputs only: `machscope` neither links against them nor ships any part
of them in its own output.

| File | Origin |
|---|---|
| `sample.c` | the source every `sample.*` fixture is built from |
| `sample.fat` | `sample.c` for arm64 and x86_64, combined with `lipo -create` |
| `sample.bin` | the arm64 executable the dSYM belongs to |
| `sample.arm64e` | the same program built with `-arch arm64e`, so the authenticated-pointer fixup path is reachable |
| `chains.c` | source for the long-chain fixture |
| `sample.chains` | `chains.c` for arm64: 65 fixups in two chains, so a walk that mis-strides is visible |
| `classic.c` | source for the pre-chained-fixup fixture |
| `sample.classic` | `classic.c` for x86_64: `LC_DYLD_INFO_ONLY` opcode streams, no chained fixups |
| `sample.dsym` | the dSYM companion `dsymutil` produced for the arm64 slice |
| `sample.dwarf4` | the same program emitted with `-gdwarf-4`, so the pre-5 line-table layout is exercised |
| `entitled.c` | source for the binary the entitlement blobs were taken from |
| `entitled.plist` | the entitlements file that binary was signed with |
| `entitlements.der` | slot 7 payload, DER-encoded, extracted from that binary |
| `entitlements.xml` | slot 5 payload, plist XML, extracted from that binary |

## Why these are generated rather than committed from elsewhere

An earlier revision of this repository shipped three copies of `/bin/ls` as
fixtures. That is a redistribution of an Apple binary — the `ls` in it even
carries a Regents-of-the-University-of-California copyright notice — and it is
not something a package declaring `Apache-2.0` can do. The fixtures are now
built from our own source, and `make_fixtures.sh` is checked in so that anyone
can regenerate them and compare.

The script passes `-fdebug-compilation-dir=.` when compiling, so the committed
dSYM records `.` rather than the home directory of whoever built it: a fixture
that carries a build machine's path is both a small privacy leak and a file that
differs between machines.

It also pins each object file's modification time with `touch -t` before
linking. The linker writes that timestamp into every `N_OSO` debug-map entry as
its `n_value`, so without the pin two builds of byte-identical compiler output
differ in the committed fixture, and the script's claim to regenerate the
committed bytes is not true. Two full runs of the script now produce identical
files; that is checked before the fixtures are committed.

`sample.arm64e` exists for a specific reason. A plain arm64 build reaches only
the unauthenticated pointer formats; arm64e is what makes clang emit
`DYLD_CHAINED_PTR_ARM64E_USERLAND24` slots with a signing key and an address
discriminator, which is the branch of `decode_slot` that would otherwise be
dead code as far as the tests are concerned.

`sample.classic` covers the other fixup encoding. Before chained fixups, an
image described its relocations with two opcode streams named by
`LC_DYLD_INFO_ONLY`; the linker emits chained fixups by default now, so the
fixture is built with `-no_fixup_chains`. Without it the classic decoder had no
test, which is how a version that returned an empty array for such images looked
correct: every fixture happened to be chained. In `/usr/bin` there are 71 slices
that take the classic path, including `ls`, `cp` and `mv`.

`sample.chains` exists for a different reason, and it is a bug this repository
shipped. `next` — the field giving the distance to the next slot — sits at bit
51 in every pointer format, but the code read the stride out of the low 12 bits,
which are the low bits of `target`. Every fixture here had exactly one fixup, so
every fixture still passed: a chain of length one never reads `next`. Against
`/usr/bin/ssh` the walk reported 12 of 1024 slots. Nothing with a single fixup
can catch that, so `chains.c` declares 64 `static` pointers to string literals,
which ld64 relocates into one `__DATA,__data` run of 64 consecutive links. Both
kinds of edge are then present in one file: 64 rebases and one bind.

## The entitlement blobs

`entitlements.der` and `entitlements.xml` are the two payloads Apple wrote for
the same dictionary, taken out of a binary built from `entitled.c` and signed
on the command line:

```
$ clang -arch arm64 -o entitled internal/fixtures/entitled.c
$ codesign --entitlements internal/fixtures/entitled.plist -s - --force entitled
$ codesign -d --entitlements :- entitled
<?xml version="1.0" encoding="UTF-8"?>...
<key>com.apple.security.get-task-allow</key><true/>
<key>com.example.counter</key><integer>42</integer>
<key>com.example.label</key><string>machscope</string>
<key>com.example.list</key><array><string>a</string><integer>7</integer></array>
<key>com.example.nested</key><dict><key>inner</key><string>deep</string></dict>
```

Only the two payloads are stored, not the signed binary: `codesign` embeds a
signing timestamp, so re-running it does not reproduce the same bytes, and a
fixture that cannot be regenerated is a fixture nobody can audit. The payloads
are what the decoder consumes and they are byte-stable once extracted.

Slot 5 holds plist XML (`CSMAGIC_EMBEDDED_ENTITLEMENTS`) and slot 7 holds the
DER form (`CSMAGIC_EMBEDDED_DER_ENTITLEMENTS`). `CSSLOT_SIGNATURESLOT`
(`0x10000`) holds the CMS signature over the code directory and carries no
entitlements; `/bin/ls` has that slot but no entitlement slot at all, which
`signature_wbtest.mbt` now asserts.

Expected values in `oracle_wbtest.mbt` were taken from `otool -h` and
`otool -f` on these generated files:

```
$ otool -h internal/fixtures/sample.arm64e
      magic  cputype cpusubtype  caps    filetype ncmds sizeofcmds      flags
 0xfeedfacf 16777228          2  0x81           2    17       1056 0x00200085
```
## Why there is a DWARF 4 fixture as well

`sample.dsym` is DWARF 5, whose line-program prologue describes its file table
with a list of (content type, form) pairs. Versions 2 through 4 use two
NUL-terminated string lists and a `header_length` that locates the opcode
stream. The two layouts share almost no code, and until `sample.dwarf4` existed
the pre-5 path had no fixture — the address arithmetic in it was wrong and
nothing noticed. `sample.dwarf4` is the same `sample.c` built with `-gdwarf-4`,
and the tests assert that both versions map the same address to the same source
line.
