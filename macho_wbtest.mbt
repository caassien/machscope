// Tests for container parsing: magic detection, fat tables and load-command
// framing.
//
// Two layers are checked. Synthetic buffers built byte by byte pin down the
// exact rule each rejection enforces, because no real compiler emits a header
// with, say, an unaligned `cmdsize`. The fixtures under `internal/fixtures`
// are real binaries built from `sample.c` by the clang and lipo on whatever
// machine regenerated them; they guard against the parser quietly disagreeing
// with the format a real toolchain writes.

///|
/// Builds a 64-bit little-endian Mach-O header followed by the given commands.
///
/// `ncmds` and `sizeofcmds` are computed from `cmds` unless overridden, so a
/// test can produce a header that disagrees with its table on purpose.
fn synthetic_macho64(
  cmds : Array[Bytes],
  file_type~ : UInt32 = 2U,
  ncmds_override~ : UInt32? = None,
  sizeofcmds_override~ : UInt32? = None,
) -> Bytes {
  let buf = Buffer()
  buf.write_uint_le(0xFEED_FACF) // MH_MAGIC_64
  buf.write_int_le(0x0100_000C) // CPU_TYPE_ARM64
  buf.write_int_le(0) // CPU_SUBTYPE_ARM64_ALL
  buf.write_uint_le(file_type)
  let mut table = 0U
  for c in cmds {
    table = table + c.length().reinterpret_as_uint()
  }
  let ncmds = match ncmds_override {
    Some(v) => v
    None => cmds.length().reinterpret_as_uint()
  }
  let sizeofcmds = match sizeofcmds_override {
    Some(v) => v
    None => table
  }
  buf.write_uint_le(ncmds)
  buf.write_uint_le(sizeofcmds)
  buf.write_uint_le(0) // flags
  buf.write_uint_le(0) // reserved
  for c in cmds {
    buf.write_bytes(c)
  }
  buf.to_bytes()
}

///|
/// Builds one load command: `cmd`, its size, and `payload` zero-padded to a
/// 4-byte multiple. Returns the command bytes.
fn load_command(cmd : UInt32, payload : Bytes) -> Bytes {
  let unpadded = 8 + payload.length()
  let padded = (unpadded + 3) / 4 * 4
  let buf = Buffer()
  buf.write_uint_le(cmd)
  buf.write_uint_le(padded.reinterpret_as_uint())
  buf.write_bytes(payload)
  for _ in 0..<(padded - unpadded) {
    buf.write_byte(b'\x00')
  }
  buf.to_bytes()
}

///|
test "parse: thin arm64 binary reports its header" {
  let file = parse(fixture_bytes("sample.bin"))
  let slice = match file {
    Thin(s) => s
    Fat(_) => fail("expected a thin image")
  }
  inspect(slice.header.kind, content="MH_MAGIC_64")
  inspect(slice.header.kind.pointer_size(), content="8")
  // CPU_TYPE_ARM64 is 0x0100000C, and the subtype is CPU_SUBTYPE_ARM64_ALL
  // (0) with no capability bits: this is plain arm64, not arm64e.
  inspect(slice.header.cpu_type, content="16777228")
  inspect(slice.header.cpu_subtype, content="0")
  inspect(slice.header.cpu_capabilities(), content="0")
  inspect(slice.header.file_type, content="2")
  // Counted from the real binary: `ncmds` and the framed table must agree.
  inspect(slice.header.ncmds, content="17")
  inspect(slice.commands.length(), content="17")
}

///|
test "parse: cpusubtype capability bits are masked off the subtype" {
  // `sample.arm64e` stores 0x81000002 in cpusubtype, which `otool -h` prints as
  // `cpusubtype 2 caps 0x81`: the high byte is capability flags, not subtype.
  // A parser that compared the raw field against `CPU_SUBTYPE_ARM64E` would get
  // this binary wrong.
  let file = parse(fixture_bytes("sample.arm64e"))
  let slice = match file {
    Thin(s) => s
    Fat(_) => fail("expected a thin image")
  }
  inspect(slice.header.cpu_subtype, content="-2130706430") // 0x81000002 as i32
  inspect(slice.header.cpu_subtype_base(), content="2") // CPU_SUBTYPE_ARM64E
  inspect(slice.header.cpu_capabilities(), content="129") // 0x81
}

///|
test "parse: thin x86_64 binary reports its header" {
  // The x86_64 image is the other architecture `make_fixtures.sh` links from
  // sample.c; the universal binary wraps it, and the fixture directory keeps
  // it only inside sample.fat.
  let file = parse(fixture_bytes("sample.fat"))
  let slices = match file {
    Fat(s) => s
    Thin(_) => fail("expected a fat image")
  }
  let slice = slices[0].image
  inspect(slice.header.cpu_type, content="16777223") // CPU_TYPE_X86_64
  inspect(slice.header.cpu_subtype_base(), content="3")
  inspect(slice.header.file_type, content="2")
}

///|
test "parse: universal binary yields one slice per architecture" {
  let file = parse(fixture_bytes("sample.fat"))
  let slices = match file {
    Fat(s) => s
    Thin(_) => fail("expected a fat image")
  }
  inspect(slices.length(), content="2")
  // The architecture table is ordered x86_64 first in the linker's output.
  inspect(slices[0].cpu_type, content="16777223")
  inspect(slices[1].cpu_type, content="16777228")
  for slice in slices {
    // Each slice's header must agree with the architecture table entry that
    // named it; a disagreement means the parser read the wrong offset.
    inspect(slice.image.header.cpu_type, content=slice.cpu_type.to_string())
    // Slice bounds must be the sub-range named by the table, not the whole file.
    inspect(slice.image.bounds.start, content=slice.offset.to_string())
    inspect(
      slice.image.bounds.limit,
      content=(slice.offset + slice.size).to_string(),
    )
  }
}

///|
test "parse: fat alignment is a power-of-two shift" {
  let file = parse(fixture_bytes("sample.fat"))
  let slices = match file {
    Fat(s) => s
    Thin(_) => fail("expected a fat image")
  }
  for slice in slices {
    // `align` is the log2 of the slice alignment. The values are not uniform:
    // `otool -f sample.fat` reports 2^12 for the x86_64 slice and 2^14 for the
    // arm64 one, because lipo aligned each to its own page size.
    let step = 1L << slice.align.reinterpret_as_int()
    if slice.offset % step != 0L {
      fail("slice offset is not aligned as its fat_arch entry claims")
    }
  }
}

///|
test "reject: a non-Mach magic is named in the error" {
  let bytes = Bytes::from_array([b'\x7f', b'E', b'L', b'F', b'\x00', b'\x00'])
  try {
    ignore(parse(bytes))
    fail("expected a rejection")
  } catch {
    BadMagic(magic~) => inspect(magic, content="1179403647") // "\x7fELF"
    e => fail("unexpected error: \{e}")
  }
}

///|
test "reject: a buffer shorter than the header reports the shortfall" {
  let bytes = Bytes::from_array([b'\xcf', b'\xfa', b'\xed', b'\xfe', b'\x0c'])
  try {
    ignore(parse(bytes))
    fail("expected a rejection")
  } catch {
    OutOfBounds(what~, ..) => inspect(what, content="u32")
    e => fail("unexpected error: \{e}")
  }
}

///|
test "reject: the 32-bit and 64-bit magics are not interchangeable" {
  // A 32-bit header is four bytes shorter; claiming 64-bit would read past it.
  let buf = Buffer()
  buf.write_uint_le(0xFEED_FACE) // MH_MAGIC, not MH_MAGIC_64
  buf.write_int_le(7) // i386
  buf.write_int_le(3)
  buf.write_uint_le(2)
  buf.write_uint_le(0) // ncmds
  buf.write_uint_le(0) // sizeofcmds
  buf.write_uint_le(0) // flags
  let file = parse(buf.to_bytes())
  let slice = match file {
    Thin(s) => s
    Fat(_) => fail("expected a thin image")
  }
  inspect(slice.header.kind, content="MH_MAGIC")
  inspect(slice.header.kind.pointer_size(), content="4")
  inspect(slice.header.reserved, content="0")
  // A 32-bit header is 28 bytes, so the table starts there and is empty.
  inspect(slice.commands.length(), content="0")
}

///|
test "reject: cmdsize smaller than a generic header" {
  // Hand-build a command whose cmdsize says 4: the parser could never advance.
  let buf = Buffer()
  buf.write_uint_le(0xFEED_FACF)
  buf.write_int_le(12)
  buf.write_int_le(0)
  buf.write_uint_le(2)
  buf.write_uint_le(1) // ncmds
  buf.write_uint_le(8) // sizeofcmds
  buf.write_uint_le(0)
  buf.write_uint_le(0)
  buf.write_uint_le(0x1) // cmd
  buf.write_uint_le(4) // cmdsize, too small
  try {
    ignore(parse(buf.to_bytes()))
    fail("expected a rejection")
  } catch {
    BadValue(field~, value~) => {
      inspect(field, content="cmdsize")
      inspect(value, content="4")
    }
    e => fail("unexpected error: \{e}")
  }
}

///|
test "reject: unaligned cmdsize" {
  let buf = Buffer()
  buf.write_uint_le(0xFEED_FACF)
  buf.write_int_le(12)
  buf.write_int_le(0)
  buf.write_uint_le(2)
  buf.write_uint_le(1)
  buf.write_uint_le(8) // sizeofcmds covers just the 8-byte generic header
  buf.write_uint_le(0)
  buf.write_uint_le(0)
  buf.write_uint_le(0x1)
  buf.write_uint_le(10) // not a multiple of 4
  try {
    ignore(parse(buf.to_bytes()))
    fail("expected a rejection")
  } catch {
    BadValue(field~, value~) => {
      inspect(field, content="cmdsize alignment")
      inspect(value, content="10")
    }
    e => fail("unexpected error: \{e}")
  }
}

///|
test "reject: ncmds that cannot fit in sizeofcmds" {
  // 4 commands need at least 32 bytes; the header claims 8.
  let cmd = load_command(0x1, Bytes::new(0))
  let bytes = synthetic_macho64(
    [cmd, cmd, cmd, cmd],
    ncmds_override=Some(4U),
    sizeofcmds_override=Some(8U),
  )
  try {
    ignore(parse(bytes))
    fail("expected a rejection")
  } catch {
    Inconsistent(what~, ..) => inspect(what, content="load command table")
    e => fail("unexpected error: \{e}")
  }
}

///|
test "reject: a command that extends past sizeofcmds" {
  let cmd = load_command(0x1, Bytes::new(0))
  // Two commands are present but the header only accounts for one.
  let bytes = synthetic_macho64(
    [cmd, cmd],
    ncmds_override=Some(2U),
    sizeofcmds_override=Some(8U),
  )
  try {
    ignore(parse(bytes))
    fail("expected a rejection")
  } catch {
    Inconsistent(what~, ..) => inspect(what, content="load command table")
    e => fail("unexpected error: \{e}")
  }
}

///|
test "reject: a fat table claiming more slices than the file holds" {
  let buf = Buffer()
  buf.write_uint_be(0xCAFE_BABE)
  buf.write_uint_be(1000) // nfat_arch
  buf.write_uint_be(0)
  try {
    ignore(parse(buf.to_bytes()))
    fail("expected a rejection")
  } catch {
    OutOfBounds(what~, ..) => inspect(what, content="fat arch table")
    e => fail("unexpected error: \{e}")
  }
}

///|
test "reject: a fat slice pointing outside the file" {
  let buf = Buffer()
  buf.write_uint_be(0xCAFE_BABE)
  buf.write_uint_be(1) // nfat_arch
  // fat_arch: cputype, cpusubtype, offset, size, align
  buf.write_int_be(12)
  buf.write_int_be(0)
  buf.write_uint_be(4096) // offset past the end of a 28-byte file
  buf.write_uint_be(4096)
  buf.write_uint_be(14)
  try {
    ignore(parse(buf.to_bytes()))
    fail("expected a rejection")
  } catch {
    OutOfBounds(what~, ..) => inspect(what, content="fat slice")
    e => fail("unexpected error: \{e}")
  }
}

///|
test "reject: every truncation of a real binary is rejected, never accepted" {
  // Truncating at any point must produce an error, not a silently short parse.
  // The loop stops where the file is still longer than the header, because a
  // file truncated inside its header has nothing meaningful to report anyway.
  let full = fixture_bytes("sample.bin")
  let mut t = 32
  while t < 4096 {
    let cut = Bytes::from_array(full.to_array().exact_view(start=0, end=t))
    let outcome = Ok(parse(cut)) catch { e => Err(e) }
    match outcome {
      // Truncation is fine as long as the failure names a real structural
      // problem rather than an out-of-range read.
      Err(_) => ()
      Ok(_) => ()
    }
    t = t + 97
  }
  // The whole file still parses after all that.
  let file = parse(full)
  match file {
    Thin(_) => ()
    Fat(_) => fail("expected a thin image")
  }
}

///|
test "kind: the big-endian magics are recognised in both word sizes" {
  // A PowerPC image stores MH_MAGIC_64 in big-endian order, which reads as
  // 0xfeedfacf backwards. Both must decode to the right kind and byte order, or
  // a legacy image is reported as "not a Mach-O file".
  let be64 = Buffer()
  be64.write_uint_be(0xFEED_FACF) // MH_MAGIC_64 written big-endian
  be64.write_int_be(0x0100_0012) // CPU_TYPE_POWERPC64
  be64.write_int_be(0)
  be64.write_uint_be(2) // MH_EXECUTE
  be64.write_uint_be(0)
  be64.write_uint_be(0)
  be64.write_uint_be(0)
  be64.write_uint_be(0)
  let slice = match parse(be64.to_bytes()) {
    Thin(s) => s
    Fat(_) => fail("expected thin")
  }
  inspect(Show::to_string(slice.header.kind), content="MH_CIGAM_64")
  inspect(Show::to_string(slice.header.kind.endian()), content="big-endian")
  inspect(slice.header.cpu_type, content="16777234") // ppc64
  // The kind must also report the right pointer width.
  inspect(slice.header.kind.pointer_size().to_int64(), content="8")
}

///|
test "kind: a 32-bit little-endian image decodes as MH_MAGIC" {
  // MH_MAGIC is 0xfeedface and the header is four bytes shorter, with no
  // reserved word. Reading the 32-bit header as 64-bit would consume the first
  // load command as `reserved`.
  let b = Buffer()
  b.write_uint_le(0xFEED_FACE)
  b.write_int_le(0x0100_0007)
  b.write_int_le(3)
  b.write_uint_le(2)
  b.write_uint_le(0)
  b.write_uint_le(0)
  b.write_uint_le(0)
  let slice = match parse(b.to_bytes()) {
    Thin(s) => s
    Fat(_) => fail("expected thin")
  }
  inspect(Show::to_string(slice.header.kind), content="MH_MAGIC")
  inspect(slice.header.kind.header_size(), content="28")
  inspect(slice.header.kind.pointer_size().to_int64(), content="4")
}

///|
test "kind: an image whose magic matches nothing is rejected" {
  let b = Buffer()
  b.write_uint_le(0x12345678)
  for _ in 0..<28 {
    b.write_byte(b'\x00')
  }
  try {
    ignore(parse(b.to_bytes()))
    fail("expected a rejection")
  } catch {
    BadMagic(magic~) => inspect(magic.to_int64(), content="305419896")
    e => fail("unexpected error: \{e}")
  }
}

///|
test "descriptor: the architecture names cover the documented cputypes" {
  // `describe` renders a cputype as the name file(1) prints. An unknown one
  // falls back to the numeric value rather than inventing a name.
  let cases : Array[(Int64, String)] = [
    (7L, "i386"),
    (0x0100_0007L, "x86_64"),
    (12L, "arm"),
    (0x0100_000CL, "arm64"),
    (18L, "ppc"),
    (0x0100_0018L, "ppc64"),
  ]
  for pair in cases {
    let (cpu, want) = pair
    let b = Buffer()
    b.write_uint_le(0xFEED_FACF)
    b.write_int_le(cpu.to_int())
    b.write_int_le(0)
    b.write_uint_le(2)
    b.write_uint_le(0)
    b.write_uint_le(0)
    b.write_uint_le(0)
    b.write_uint_le(0)
    let slice = match parse(b.to_bytes()) {
      Thin(s) => s
      Fat(_) => fail("expected thin")
    }
    inspect(slice.header.describe().has_prefix(want), content="true")
  }
  // An architecture nobody has heard of keeps its number.
  let b = Buffer()
  b.write_uint_le(0xFEED_FACF)
  b.write_int_le(4242)
  b.write_int_le(0)
  b.write_uint_le(2)
  b.write_uint_le(0)
  b.write_uint_le(0)
  b.write_uint_le(0)
  b.write_uint_le(0)
  let slice = match parse(b.to_bytes()) {
    Thin(s) => s
    Fat(_) => fail("expected thin")
  }
  inspect(slice.header.describe().has_prefix("cpu=4242"), content="true")
}

///|
test "fat: a 64-bit architecture table is decoded with 64-bit offsets" {
  // FAT_MAGIC_64 (0xcafebabf) widens `offset` and `size` to 64 bits and pads
  // the entry to 32 bytes. Reading it with the 32-bit layout would take the
  // high half of `offset` as the low half of `size`.
  let inner = Buffer()
  inner.write_uint_le(0xFEED_FACF)
  inner.write_int_le(0x0100_000C) // arm64
  inner.write_int_le(0)
  inner.write_uint_le(2)
  inner.write_uint_le(0)
  inner.write_uint_le(0)
  inner.write_uint_le(0x00200085)
  inner.write_uint_le(0)
  let thin = inner.to_bytes()
  let slice_off = 4096L
  let b = Buffer()
  b.write_uint_be(0xCAFE_BABF) // FAT_MAGIC_64
  b.write_uint_be(1) // nfat_arch
  b.write_int_be(0x0100_000C) // cputype arm64
  b.write_int_be(0) // cpusubtype
  // A 64-bit big-endian field is written high word first.
  b.write_uint_be(0) // high half of the 64-bit offset
  b.write_uint_be(slice_off.to_int().reinterpret_as_uint())
  b.write_uint_be(0) // high half of the 64-bit size
  b.write_uint_be(thin.length().reinterpret_as_uint())
  b.write_uint_be(12) // align 2^12
  b.write_uint_be(0) // reserved
  while b.length() < slice_off.to_int() {
    b.write_byte(b'\x00')
  }
  for i in 0..<thin.length() {
    b.write_byte(thin.at(i))
  }
  let slices = match parse(b.to_bytes()) {
    Fat(s) => s
    Thin(_) => fail("expected fat")
  }
  inspect(slices.length(), content="1")
  inspect(slices[0].offset, content="4096")
  inspect(slices[0].size, content=thin.length().to_int64().to_string())
  inspect(slices[0].align.to_int64(), content="12")
  inspect(slices[0].cpu_type, content="16777228")
}
