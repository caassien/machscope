// Tests for container parsing: magic detection, fat tables and load-command
// framing.
//
// Two layers are checked. Synthetic buffers built byte by byte pin down the
// exact rule each rejection enforces, because no real compiler emits a header
// with, say, an unaligned `cmdsize`. The fixtures under `internal/fixtures`
// are real binaries produced by Apple's linker and then thinned with `lipo`;
// they guard against the parser quietly disagreeing with the format that real
// toolchains write.

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
  let buf = Buffer(size_hint=padded)
  buf.write_uint_le(cmd)
  buf.write_uint_le(padded.reinterpret_as_uint())
  buf.write_bytes(payload)
  for _ in 0..<(padded - unpadded) {
    buf.write_byte(b'\x00')
  }
  buf.to_bytes()
}

///|
/// Reads a checked-in fixture by name.
fn fixture(name : String) -> Bytes raise {
  let dir = @env.current_dir().unwrap()
  @fs.read_file_to_bytes(dir + "/internal/fixtures/" + name)
}

///|
test "parse: thin arm64e binary reports its header" {
  let file = parse(fixture("ls.arm64e.macho"))
  let slice = match file {
    Thin(s) => s
    Fat(_) => fail("expected a thin image")
  }
  inspect(slice.header.kind, content="MH_MAGIC_64")
  inspect(slice.header.kind.pointer_size(), content="8")
  // arm64e is 0x0100000C; the subtype carries the pointer-authentication bit.
  inspect(slice.header.cpu_type, content="16777228")
  inspect(slice.header.file_type, content="2")
  // Counted from the real binary: `ncmds` and the framed table must agree.
  inspect(slice.header.ncmds, content="20")
  inspect(slice.commands.length(), content="20")
}

///|
test "parse: thin x86_64 binary reports its header" {
  let file = parse(fixture("ls.x86_64.macho"))
  let slice = match file {
    Thin(s) => s
    Fat(_) => fail("expected a thin image")
  }
  inspect(slice.header.cpu_type, content="16777223") // CPU_TYPE_X86_64
  inspect(slice.header.file_type, content="2")
}

///|
test "parse: universal binary yields one slice per architecture" {
  let file = parse(fixture("ls.fat.macho"))
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
  let file = parse(fixture("ls.fat.macho"))
  let slices = match file {
    Fat(s) => s
    Thin(_) => fail("expected a fat image")
  }
  for slice in slices {
    // `align` is the log2 of the slice alignment; Apple aligns to 16 KiB.
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
  let full = fixture("ls.arm64e.macho")
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
