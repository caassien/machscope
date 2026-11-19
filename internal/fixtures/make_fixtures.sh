#!/bin/sh
# Regenerates every fixture in this directory from source in this repository.
#
# Run from the repository root:
#
#     sh internal/fixtures/make_fixtures.sh
#
# Requires a macOS host with the Xcode command line tools: `clang`, `lipo`,
# `dsymutil` and `codesign`. The point of generating them rather than committing
# binaries someone else built is that the inputs stay auditable: every byte the
# tests parse is traceable to a source file here plus a compiler invocation
# written down below.

set -eu

here=$(cd "$(dirname "$0")" && pwd)
cd "$here"

# `sample.*`: the general-purpose fixtures. They are compiled unoptimised so the
# line tables keep one row per statement, which is what the DWARF tests assert
# against, and so that `helper` is not inlined away before the export trie is
# written.
#
# Compiling and linking are separate steps on purpose: a one-shot `clang -g`
# deletes the object file it generated, and `dsymutil` below needs the debug map
# in the binary to still resolve.
#
# Three flags pin the output so that a rebuild is byte-identical to what is
# committed, and so that no fixture carries a path from the machine that built
# it.
#
#   -fdebug-compilation-dir=.  records "." as the compilation directory rather
#                              than an absolute path.
#   -frandom-seed=machscope    pins the seed clang draws from the clock when it
#                              names internal symbols.
#   -Wl,-oso_prefix,.          makes the linker's `N_OSO` debug-map entry
#                              relative. Without it that entry records the
#                              object file's absolute path, which embeds the
#                              builder's home directory in a committed and
#                              published file.
#
# Note that the debug map is deliberately kept: the `N_OSO`/`N_SO`/`N_FUN`
# entries it contributes are what the symbol-table tests decode, and stripping
# them with `strip -S` would take that coverage away to solve a problem
# `-oso_prefix` solves directly.
#
# LC_UUID is kept rather than suppressed. With `-frandom-seed` set, ld64
# derives it deterministically from the contents, so it does not break
# reproducibility, and `dyld_info` refuses to read a binary that lacks it.
CLANG_FLAGS="-g -O0 -fdebug-compilation-dir=. -frandom-seed=machscope"
LDFLAGS="-Wl,-oso_prefix,."

# The linker writes each `N_OSO` debug-map entry's `n_value` as the object
# file's modification time, so two builds a second apart differ in a committed
# fixture even when every byte the compiler emitted is identical. Pinning the
# timestamp is what makes a rebuild reproduce the committed file; without it the
# dSYM and the executables carry the wall clock of whoever ran this script.
STAMP=202001010000

# Compile then link. The `touch` is the fix described above; it has to land
# between the two steps, because it is the linker that reads the timestamp.
build_thin() { # arch, object, output
  clang -arch "$1" $CLANG_FLAGS -c -o "$2" sample.c
  touch -t $STAMP "$2"
  clang -arch "$1" $LDFLAGS "$2" -o "$3"
}

build_thin arm64  sample.arm64.o  sample.arm64
build_thin x86_64 sample.x86_64.o sample.x86_64

# `sample.chains`: the fixture whose fixup chain is long enough to walk. Every
# other fixture carries a single fixup, which cannot distinguish a walk that
# follows `next` from one that reads the stride out of the wrong bits. See
# `chains.c` for why 64 relocations are enough to tell the two apart.
clang -arch arm64 $CLANG_FLAGS -c -o sample.chains.o chains.c
touch -t $STAMP sample.chains.o
clang -arch arm64 $LDFLAGS sample.chains.o -o sample.chains

# `sample.classic`: the pre-chained-fixup encoding, `LC_DYLD_INFO_ONLY` plus two
# opcode streams. The linker emits chained fixups by default now, so this needs
# `-no_fixup_chains` to produce the old form. Without this fixture the classic
# decoder had no test at all, which is why a parser that returned an empty array
# for those images looked correct: every fixture happened to be chained.
clang -arch x86_64 $CLANG_FLAGS -c -o sample.classic.o classic.c
touch -t $STAMP sample.classic.o
clang -arch x86_64 $LDFLAGS -Wl,-no_fixup_chains sample.classic.o \
      -o sample.classic

# `sample.weak`: one weakly defined function in the export trie, so the
# `EXPORT_SYMBOL_FLAGS_WEAK_DEFINITION` branch has a set bit to read. Every
# other fixture exports only strong definitions, and a flag bit that is never
# set cannot be tested by asserting the flag is false.
clang -arch arm64 $CLANG_FLAGS -c -o sample.weak.o weak.c
touch -t $STAMP sample.weak.o
clang -arch arm64 $LDFLAGS sample.weak.o -o sample.weak

# `sample.arm64e`: the same program built for arm64e, which is what makes the
# authenticated-pointer branch of `decode_slot` reachable. arm64e fixes up
# imports through `__auth_got` with a signing key and a diversity value packed
# into the slot; a plain arm64 build never produces one.
build_thin arm64e sample.arm64e.o sample.arm64e

# `sample.dwarf4`: the same program emitted with `-gdwarf-4`. The default is
# DWARF 5, whose prologue describes its file table with form descriptions;
# versions 2 through 4 use two NUL-terminated string lists instead. Both
# layouts are decoded, so both need a fixture or one of them is untested code.
clang -arch arm64 -g -gdwarf-4 -O0 -fdebug-compilation-dir=. \
      -frandom-seed=machscope -c -o sample.dwarf4.o sample.c
touch -t $STAMP sample.dwarf4.o
clang -arch arm64 $LDFLAGS sample.dwarf4.o -o sample.dwarf4.bin
dsymutil -o dwarf4.dSYM sample.dwarf4.bin
cp dwarf4.dSYM/Contents/Resources/DWARF/sample.dwarf4.bin sample.dwarf4

# The dSYM companion for the arm64 slice. `dsymutil` reads the debug map the
# linker left in the binary and rewrites the DWARF into a standalone file, which
# is the form a crash report is symbolicated against.
#
# The bundle is built under a name that does not collide with the fixture it
# produces. On a case-insensitive filesystem — the default on macOS — writing
# `sample.dsym` while a directory `sample.dSYM` exists copies *into* that
# directory rather than replacing it, which silently yields a checkout that
# only works on Linux.
dsymutil -o build.dSYM sample.arm64
cp build.dSYM/Contents/Resources/DWARF/sample.arm64 sample.dsym

lipo -create sample.arm64 sample.x86_64 -output sample.fat
lipo -thin arm64  sample.fat -output sample.arm64.thin
lipo -thin x86_64 sample.fat -output sample.x86_64.thin

# `sample.bin` is the arm64 executable the dSYM belongs to.
cp sample.arm64 sample.bin

# `entitled.*`: a binary carrying entitlements, so that the code-signature tests
# have a payload in slots 5 and 7. An ad-hoc signature (`-s -`) is enough; no
# signing identity is required and nothing here is distributed to anyone.
clang -arch arm64 -g -O0 -o entitled.bin entitled.c
codesign --entitlements entitled.plist -s - --force entitled.bin

# The tests consume the two payloads rather than the signed binary, because
# `codesign` embeds a signing timestamp and the binary therefore differs on
# every run. The payloads do not.
python3 - <<'PY'
import struct, sys

data = open('entitled.bin', 'rb').read()
magic, ncmds, _ = struct.unpack_from('<Iii', data, 0)
at = 32
sig = None
for _ in range(ncmds):
    cmd, size = struct.unpack_from('<II', data, at)
    if cmd == 0x1D:                       # LC_CODE_SIGNATURE
        sig = struct.unpack_from('<II', data, at + 8)
        break
    at += size
if sig is None:
    sys.exit('entitled.bin has no LC_CODE_SIGNATURE')

dataoff, datasize = sig
superblob = data[dataoff:dataoff + datasize]
count = struct.unpack_from('>I', superblob, 8)[0]
written = set()
for i in range(count):
    slot, off = struct.unpack_from('>II', superblob, 12 + i * 8)
    blob_magic, blob_len = struct.unpack_from('>II', superblob, off)
    payload = superblob[off + 8:off + blob_len]
    if slot == 5 and blob_magic == 0xFADE7171:
        open('entitlements.xml', 'wb').write(payload)
        written.add('xml')
    elif slot == 7 and blob_magic == 0xFADE7172:
        open('entitlements.der', 'wb').write(payload)
        written.add('der')
if written != {'xml', 'der'}:
    sys.exit('expected both an XML and a DER entitlement blob, got %s' % sorted(written))
PY

# Everything above is an intermediate; the repository keeps only what the tests
# read.
rm -rf sample.arm64 sample.x86_64 sample.arm64.thin sample.x86_64.thin \
       sample.arm64.o sample.x86_64.o sample.arm64e.o sample.dwarf4.o \
       sample.chains.o sample.classic.o sample.weak.o sample.dwarf4.bin \
       build.dSYM dwarf4.dSYM entitled.bin entitled.bin.dSYM

ls -l