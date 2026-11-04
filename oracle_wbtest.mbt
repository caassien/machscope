// Differential tests against Apple's own headers as an oracle.
//
// Every expected value below was copied from `otool -h` and `otool -f` run on
// the same fixture. A parser that agrees with itself proves nothing; the point
// of these tests is that it agrees with the tool the platform ships.

///|
/// Reads a fixture by name.
fn fixture_bytes(name : String) -> Bytes raise {
  let dir = @env.current_dir().unwrap()
  @fs.read_file_to_bytes(dir + "/internal/fixtures/" + name)
}

///|
test "oracle: ls.arm64e header matches otool -h" {
  // otool -h ls.arm64e.macho:
  //   magic 0xfeedfacf  cputype 16777228  cpusubtype 2 (+0x80 caps)
  //   filetype 2  ncmds 20  sizeofcmds 1712  flags 0x00200085
  let slice = match parse(fixture_bytes("ls.arm64e.macho")) {
    Thin(s) => s
    Fat(_) => fail("expected thin")
  }
  inspect(Show::to_string(slice.header.kind), content="MH_MAGIC_64")
  inspect(slice.header.cpu_type, content="16777228")
  inspect(slice.header.file_type, content="2")
  inspect(slice.header.ncmds, content="20")
  inspect(slice.header.sizeofcmds.to_int64(), content="1712")
  inspect(slice.header.flags.to_int64(), content="2097285") // 0x00200085
  // cpusubtype carries the capability bits in its high byte; masking them off
  // must recover the value otool prints in its `cpusubtype` column.
  inspect(slice.header.cpu_subtype_base(), content="2")
  inspect(slice.header.cpu_capabilities(), content="128") // 0x80 caps
}

///|
test "oracle: ls.x86_64 header matches otool -h" {
  // otool -h ls.x86_64.macho:
  //   cputype 16777223  cpusubtype 3  filetype 2  ncmds 18  sizeofcmds 1736
  let slice = match parse(fixture_bytes("ls.x86_64.macho")) {
    Thin(s) => s
    Fat(_) => fail("expected thin")
  }
  inspect(slice.header.cpu_type, content="16777223")
  inspect(slice.header.ncmds, content="18")
  inspect(slice.header.sizeofcmds.to_int64(), content="1736")
  inspect(slice.header.cpu_subtype_base(), content="3")
  inspect(slice.header.cpu_capabilities(), content="0")
}

///|
test "oracle: ls.fat architecture table matches otool -f" {
  // otool -f ls.fat.macho: arch 0 x86_64 at 16384 size 48128 align 2^14,
  //                        arch 1 arm64e at 65536 size 88672 align 2^14
  let slices = match parse(fixture_bytes("ls.fat.macho")) {
    Fat(s) => s
    Thin(_) => fail("expected fat")
  }
  inspect(slices.length(), content="2")
  inspect(slices[0].cpu_type, content="16777223")
  inspect(slices[0].cpu_subtype_base(), content="3")
  inspect(slices[0].cpu_capabilities(), content="0")
  inspect(slices[0].offset, content="16384")
  inspect(slices[0].size, content="48128")
  inspect(slices[0].align.to_int64(), content="14")
  inspect(slices[1].cpu_type, content="16777228")
  // The fat table stores the capability bits inline, unlike `otool -f`, which
  // prints them in a separate column.
  inspect(slices[1].cpu_subtype_base(), content="2")
  inspect(slices[1].cpu_capabilities(), content="128")
  inspect(slices[1].offset, content="65536")
  inspect(slices[1].size, content="88672")
  inspect(slices[1].align.to_int64(), content="14")
}

///|
test "oracle: the fat slices are byte-identical to the thinned binaries" {
  // `lipo -thin` produces exactly the slice bytes, so the parsed header must
  // match the standalone file's header field for field. This catches an
  // off-by-one in the fat offset arithmetic that field checks alone could miss.
  let fat = match parse(fixture_bytes("ls.fat.macho")) {
    Fat(s) => s
    Thin(_) => fail("expected fat")
  }
  let thin_x86 = match parse(fixture_bytes("ls.x86_64.macho")) {
    Thin(s) => s
    Fat(_) => fail("expected thin")
  }
  let thin_arm = match parse(fixture_bytes("ls.arm64e.macho")) {
    Thin(s) => s
    Fat(_) => fail("expected thin")
  }
  let a = fat[0].image.header
  let b = thin_x86.header
  inspect(a.cpu_type, content=b.cpu_type.to_string())
  inspect(a.file_type, content=b.file_type.to_string())
  inspect(a.ncmds, content=b.ncmds.to_string())
  inspect(a.sizeofcmds, content=b.sizeofcmds.to_string())
  inspect(a.flags, content=b.flags.to_string())
  let c = fat[1].image.header
  let d = thin_arm.header
  inspect(c.cpu_type, content=d.cpu_type.to_string())
  inspect(c.ncmds, content=d.ncmds.to_string())
  inspect(c.sizeofcmds, content=d.sizeofcmds.to_string())
  // The number of framed commands must equal ncmds for every slice.
  inspect(fat[0].image.commands.length(), content=b.ncmds.to_string())
  inspect(fat[1].image.commands.length(), content=d.ncmds.to_string())
}

///|
test "oracle: command framing tiles the declared table exactly" {
  // sizeofcmds is the exact width of the table, so the sum of cmdsize must
  // equal it. A framing bug shows up as a gap or an overlap at the end.
  for name in ["ls.arm64e.macho", "ls.x86_64.macho"] {
    let slice = match parse(fixture_bytes(name)) {
      Thin(s) => s
      Fat(_) => fail("expected thin")
    }
    let mut total = 0L
    for cmd in slice.commands {
      total = total + cmd.size.to_int64()
    }
    inspect(total, content=slice.header.sizeofcmds.to_int64().to_string())
  }
}
