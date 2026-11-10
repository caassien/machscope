// Differential tests against Apple's own headers as an oracle.
//
// Every `oracle:` test below compares against `otool -h` or `otool -f` run on
// the same fixture; the expected values were copied from that output. A parser
// that agrees with itself proves nothing; the point of these tests is that it
// agrees with the tool the platform ships.
//
// The tests not prefixed `oracle:` check an internal consistency the tools do
// not print — that `lipo -create` really made the fat slice out of the thin
// file, and that the framed commands tile `sizeofcmds` exactly.
//
// The fixtures are built from `internal/fixtures/sample.c` by
// `internal/fixtures/make_fixtures.sh`, so the bytes under test are ones a real
// linker produced even though no third-party binary is redistributed here.

///|
/// Reads a fixture by name.
fn fixture_bytes(name : String) -> Bytes raise {
  let dir = @env.current_dir().unwrap()
  @fs.read_file_to_bytes(dir + "/internal/fixtures/" + name)
}

///|
test "oracle: sample.bin header matches otool -h" {
  // otool -h sample.bin:
  //   magic 0xfeedfacf  cputype 16777228  cpusubtype 0  caps 0x00
  //   filetype 2  ncmds 17  sizeofcmds 1056  flags 0x00200085
  let slice = match parse(fixture_bytes("sample.bin")) {
    Thin(s) => s
    Fat(_) => fail("expected thin")
  }
  inspect(Show::to_string(slice.header.kind), content="MH_MAGIC_64")
  inspect(slice.header.cpu_type, content="16777228")
  inspect(slice.header.file_type, content="2")
  inspect(slice.header.ncmds, content="17")
  inspect(slice.header.sizeofcmds.to_int64(), content="1056")
  inspect(slice.header.flags.to_int64(), content="2097285") // 0x00200085
  // cpusubtype carries the capability bits in its high byte; masking them off
  // must recover the value otool prints in its `cpusubtype` column. This
  // fixture is plain arm64 (`CPU_SUBTYPE_ARM64_ALL`), so both values are zero;
  // the arm64e case is asserted separately below.
  inspect(slice.header.cpu_subtype_base(), content="0")
  inspect(slice.header.cpu_capabilities(), content="0")
}

///|
test "oracle: sample.arm64e header separates subtype from capability bits" {
  // otool -h sample.arm64e:
  //   magic 0xfeedfacf  cputype 16777228  cpusubtype 2  caps 0x81
  //   filetype 2  ncmds 17  sizeofcmds 1056  flags 0x00200085
  // The stored cpusubtype is 0x81000002: the low bits are `otool`'s
  // `cpusubtype` column and the high byte is its `caps` column. A parser that
  // compared the raw field against `CPU_SUBTYPE_ARM64E` (2) would conclude this
  // is not an arm64e image at all.
  let slice = match parse(fixture_bytes("sample.arm64e")) {
    Thin(s) => s
    Fat(_) => fail("expected thin")
  }
  inspect(slice.header.cpu_type, content="16777228")
  inspect(slice.header.cpu_subtype, content="-2130706430") // 0x81000002 as i32
  inspect(slice.header.cpu_subtype_base(), content="2")
  inspect(slice.header.cpu_capabilities(), content="129") // 0x81
  inspect(slice.header.ncmds, content="17")
  inspect(slice.header.sizeofcmds.to_int64(), content="1056")
}

///|
test "oracle: sample.fat architecture table matches otool -f" {
  // otool -f sample.fat: arch 0 x86_64 at 4096 size 8816 align 2^12,
  //                      arch 1 arm64 at 16384 size 33808 align 2^14
  let slices = match parse(fixture_bytes("sample.fat")) {
    Fat(s) => s
    Thin(_) => fail("expected fat")
  }
  inspect(slices.length(), content="2")
  inspect(slices[0].cpu_type, content="16777223")
  inspect(slices[0].cpu_subtype_base(), content="3")
  inspect(slices[0].cpu_capabilities(), content="0")
  inspect(slices[0].offset, content="4096")
  inspect(slices[0].size, content="8816")
  inspect(slices[0].align.to_int64(), content="12")
  inspect(slices[1].cpu_type, content="16777228")
  // The fat table stores the capability bits inline, unlike `otool -f`, which
  // prints them in a separate column.
  inspect(slices[1].cpu_subtype_base(), content="0")
  inspect(slices[1].cpu_capabilities(), content="0")
  inspect(slices[1].offset, content="16384")
  inspect(slices[1].size, content="33808")
  inspect(slices[1].align.to_int64(), content="14")
}

///|
test "oracle: each slice's own header matches otool -h on the fat file" {
  // otool -h sample.fat prints one header per architecture:
  //   x86_64: cputype 16777223 cpusubtype 3 ncmds 16 sizeofcmds 1040
  //   arm64:  cputype 16777228 cpusubtype 0 ncmds 17 sizeofcmds 1056
  let slices = match parse(fixture_bytes("sample.fat")) {
    Fat(s) => s
    Thin(_) => fail("expected fat")
  }
  let x86 = slices[0].image.header
  inspect(x86.cpu_type, content="16777223")
  inspect(x86.cpu_subtype_base(), content="3")
  inspect(x86.ncmds, content="16")
  inspect(x86.sizeofcmds.to_int64(), content="1040")
  let arm = slices[1].image.header
  inspect(arm.cpu_type, content="16777228")
  inspect(arm.ncmds, content="17")
  inspect(arm.sizeofcmds.to_int64(), content="1056")
  // The number of framed commands must equal ncmds for every slice.
  inspect(slices[0].image.commands.length(), content=x86.ncmds.to_string())
  inspect(slices[1].image.commands.length(), content=arm.ncmds.to_string())
}

///|
test "fat: the arm64 slice is byte-identical to sample.bin" {
  // `make_fixtures.sh` builds the universal binary with `lipo -create` from the
  // same two linked images it keeps as `sample.bin`, so the arm64 slice is the
  // whole of `sample.bin` and nothing else. This catches an off-by-one in the
  // fat offset arithmetic that field checks alone could miss: a slice read from
  // the wrong offset would not reproduce the standalone file byte for byte.
  let fat = match parse(fixture_bytes("sample.fat")) {
    Fat(s) => s
    Thin(_) => fail("expected fat")
  }
  let thin = fixture_bytes("sample.bin")
  let slice = fat[1]
  inspect(slice.size, content=thin.length().to_int64().to_string())
  let b = slice.image.bounds
  let mut same = true
  let mut i = 0L
  while i < thin.length().to_int64() {
    if b.bytes.at((b.start + i).to_int()) != thin.at(i.to_int()) {
      same = false
    }
    i = i + 1L
  }
  inspect(same, content="true")
}

///|
test "framing: command sizes tile the declared table exactly" {
  // sizeofcmds is the exact width of the table, so the sum of cmdsize must
  // equal it. A framing bug shows up as a gap or an overlap at the end.
  let slices : Array[MachSlice] = []
  match parse(fixture_bytes("sample.bin")) {
    Thin(s) => slices.push(s)
    Fat(_) => fail("expected thin")
  }
  match parse(fixture_bytes("sample.fat")) {
    Fat(list) =>
      for s in list {
        slices.push(s.image)
      }
    Thin(_) => fail("expected fat")
  }
  for slice in slices {
    let mut total = 0L
    for cmd in slice.commands {
      total = total + cmd.size.to_int64()
    }
    inspect(total, content=slice.header.sizeofcmds.to_int64().to_string())
  }
}
