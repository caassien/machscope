// Differential tests for DWARF line tables, against `dwarfdump --debug-line`.
//
// `sample.dsym` is a dSYM produced by `clang -g` and `dsymutil` from the
// `sample.c` checked in beside it; `internal/fixtures/make_fixtures.sh`
// regenerates both. dwarfdump prints the prologue fields and every row; the
// assertions below are copied from its output.

///|
/// The single line table of the sample dSYM, read with a fixed compilation
/// directory.
///
/// The dSYM itself records "." as `comp_dir` — the fixtures are built with
/// `-fdebug-compilation-dir=.` so that a committed fixture does not carry the
/// home directory of whoever built it. Passing "/tmp" here keeps the path
/// assertions below independent of that choice.
fn sample_table() -> LineTable raise {
  let slice = match parse(fixture_bytes("sample.dsym")) {
    Thin(s) => s
    Fat(_) => fail("expected a thin dSYM")
  }
  let tables = line_tables(slice, comp_dir="/tmp")
  if tables.length() != 1 {
    fail("expected one line program, got \{tables.length()}")
  }
  tables[0]
}

///|
test "oracle: the prologue matches dwarfdump" {
  // dwarfdump: version 5, address_size 8, min_inst_length 1,
  // max_ops_per_inst 1, default_is_stmt 1, line_base -5, line_range 14,
  // opcode_base 13.
  let t = sample_table()
  inspect(t.version.to_int64(), content="5")
  // One file and one directory in this compilation unit.
  inspect(t.files.length(), content="1")
  inspect(t.dirs.length(), content="1")
  // `dirs` comes from the prologue's directory table, which records "."
  // because the fixtures are built with `-fdebug-compilation-dir=`.
  inspect(t.dirs[0], content=".")
  inspect(t.files[0], content="sample.c")
}

///|
test "oracle: the row addresses match dwarfdump" {
  // dwarfdump --debug-line lists 24 rows starting at 0x100000460 and ending
  // with the end-of-sequence row at 0x100000528. These are the 23 live ones.
  let t = sample_table()
  let addrs : Array[String] = []
  for row in t.rows {
    if !row.end_sequence {
      addrs.push(row.address.to_string())
    }
  }
  inspect(
    addrs.join(","),
    content="4294968416,4294968432,4294968436,4294968440,4294968444,4294968448,4294968452,4294968464,4294968468,4294968472,4294968484,4294968488,4294968500,4294968504,4294968508,4294968520,4294968528,4294968532,4294968536,4294968544,4294968568,4294968576,4294968604",
  )
}

///|
test "oracle: the line and column fields match dwarfdump" {
  // The first row is line 9, column 0 — the opening brace of `compute`. The
  // next is line 10, column 7, which dwarfdump marks `prologue_end`.
  let t = sample_table()
  let live : Array[LineRow] = []
  for row in t.rows {
    if !row.end_sequence {
      live.push(row)
    }
  }
  inspect(live[0].line.to_int64(), content="9")
  inspect(live[0].column.to_int64(), content="0")
  inspect(live[1].line.to_int64(), content="10")
  inspect(live[1].column.to_int64(), content="7")
  inspect(live[1].prologue_end, content="true")
  // Rows 2 through 6 walk the `for` header on line 11.
  inspect(live[2].line.to_int64(), content="11")
  inspect(live[2].column.to_int64(), content="12")
  inspect(live[6].line.to_int64(), content="11")
  inspect(live[6].column.to_int64(), content="3")
  // The `helper` body is line 7.
  inspect(live[15].line.to_int64(), content="7")
  inspect(live[15].column.to_int64(), content="0")
}

///|
test "oracle: rows are sorted and the end-of-sequence row is last" {
  let t = sample_table()
  let mut prev = -1L
  for row in t.rows {
    if row.address < prev {
      fail("rows are not sorted by address")
    }
    prev = row.address
  }
  let last = t.rows[t.rows.length() - 1]
  inspect(last.end_sequence, content="true")
}

///|
test "lookup: a code address resolves to the source line dwarfdump reports" {
  // 0x100000490 is `helper`'s call on line 12, column 21.
  let t = sample_table()
  let loc = match lookup_address(t, 0x1_0000_0490L) {
    Some(l) => l
    None => fail("expected a location")
  }
  inspect(loc.line.to_int64(), content="12")
  inspect(loc.column.to_int64(), content="21")
  inspect(loc.file, content="/tmp/sample.c")
}

///|
test "lookup: an address between rows uses the row that governs it" {
  // 0x100000492 sits between the row at ...490 and the one at ...494, so it
  // must resolve to the ...490 row, not to the following one.
  let t = sample_table()
  let loc = match lookup_address(t, 0x1_0000_0492L) {
    Some(l) => l
    None => fail("expected a location")
  }
  inspect(loc.line.to_int64(), content="12")
  inspect(loc.column.to_int64(), content="21")
}

///|
test "lookup: an address before the first row has no location" {
  let t = sample_table()
  inspect(lookup_address(t, 0x100L) is None, content="true")
}

///|
test "lookup: the helper function's address resolves to line 7" {
  // 0x1000004d0 is the prologue_end of `helper`, on line 7.
  let t = sample_table()
  let loc = match lookup_address(t, 0x1_0000_04D0L) {
    Some(l) => l
    None => fail("expected a location")
  }
  inspect(loc.line.to_int64(), content="7")
}

///|
test "leb128: small and large values decode with the right sign" {
  let b = Bounds::of_bytes(
    Bytes::from_array([b'\x00', b'\x7f', b'\x80', b'\x01', b'\xff', b'\x00']),
  )
  let e = Endian::Little
  let (v0, c0) = read_uleb128(b, Cursor::{ pos: 0L, endian: e, })
  inspect(v0.reinterpret_as_int64(), content="0")
  let (v1, c1) = read_uleb128(b, Cursor::{ pos: 1L, endian: e, })
  inspect(v1.reinterpret_as_int64(), content="127")
  let (v2, c2) = read_uleb128(b, Cursor::{ pos: 2L, endian: e, })
  inspect(v2.reinterpret_as_int64(), content="128")
  inspect(c2.pos, content="4")
  let (v3, c3) = read_uleb128(b, Cursor::{ pos: 4L, endian: e, })
  inspect(v3.reinterpret_as_int64(), content="127")
  inspect(c3.pos, content="6")
  let _ = (c0, c1)
}

///|
test "leb128: signed values sign-extend" {
  let b = Bounds::of_bytes(Bytes::from_array([b'\x7f', b'\x3f']))
  let e = Endian::Little
  // 0x7f: -1 in SLEB128.
  let (v0, _) = read_sleb128(b, Cursor::{ pos: 0L, endian: e, })
  inspect(v0, content="-1")
  // 0x3f: 63, the last positive single-byte value.
  let (v1, _) = read_sleb128(b, Cursor::{ pos: 1L, endian: e, })
  inspect(v1, content="63")
}

///|
test "reject: a line program claiming more bytes than the section holds" {
  // Build a section whose first program declares a unit longer than the rest.
  let slice = match parse(fixture_bytes("sample.dsym")) {
    Thin(s) => s
    Fat(_) => fail("expected thin")
  }
  let sec = match debug_line_section(slice) {
    Some(s) => s
    None => fail("no __debug_line")
  }
  // A section of 8 bytes cannot hold a program whose unit_length says 4096.
  let truncated = Bounds::{
    bytes: slice.bounds.bytes,
    start: sec.file_offset.to_int64(),
    limit: sec.file_offset.to_int64() + 8L,
  }
  let tweaked = MachSlice::{
    header: slice.header,
    commands: slice.commands,
    bounds: truncated,
  }
  try {
    ignore(line_tables(tweaked))
    fail("expected a rejection")
  } catch {
    OutOfBounds(..) => ()
    e => fail("unexpected error: \{e}")
  }
}

///|
/// The line table of a DWARF 4 dSYM, read the same way.
fn dwarf4_table() -> LineTable raise {
  let slice = match parse(fixture_bytes("sample.dwarf4")) {
    Thin(s) => s
    Fat(_) => fail("expected a thin dSYM")
  }
  let tables = line_tables(slice, comp_dir="/build")
  if tables.length() != 1 {
    fail("expected one line program, got \{tables.length()}")
  }
  tables[0]
}

///|
test "oracle: a DWARF 4 prologue decodes through the pre-5 path" {
  // `sample.dwarf4` is sample.c emitted with `-gdwarf-4`. dwarfdump reports
  //   version 4  min_inst_length 1  max_ops_per_inst 1  default_is_stmt 1
  //   line_base -5  line_range 14  opcode_base 13
  // Versions 2-4 describe their file table as two NUL-terminated string lists
  // rather than the form-described tables DWARF 5 uses, so this exercises a
  // different branch of the prologue parser than sample.dsym does.
  let t = dwarf4_table()
  inspect(t.version.to_int64(), content="4")
  // In DWARF 4 the file list is 1-based and the fixture has one entry.
  inspect(t.files.length(), content="1")
  inspect(t.files[0], content="sample.c")
}

///|
test "oracle: a DWARF 4 row maps an address to the same source line" {
  // dwarfdump --debug-line sample.dwarf4 puts 0x100000470 at line 10,
  // column 7, marked prologue_end. The same source compiled at DWARF 5
  // produces the same row, so a difference here would mean the version
  // dispatch, not the program, is wrong.
  let t = dwarf4_table()
  let loc = match lookup_address(t, 0x1_0000_0470L) {
    Some(l) => l
    None => fail("expected a location")
  }
  inspect(loc.line.to_int64(), content="10")
  inspect(loc.column.to_int64(), content="7")
  // File indices are 1-based before DWARF 5, so index 1 is files[0].
  inspect(loc.file, content="/build/sample.c")
}

///|
test "oracle: the DWARF 4 and DWARF 5 tables agree on the row count" {
  // Both were built from the same source at -O0, so the statement list is the
  // same length. A version-dependent bug in the opcode loop would show up as a
  // different number of emitted rows.
  let four = dwarf4_table()
  let five = sample_table()
  inspect(four.rows.length(), content=five.rows.length().to_string())
}

///|
/// `segname` / `sectname` fields, exactly 16 bytes each with NUL padding.
let segname_dwarf : Bytes = Bytes::from_array([
  b'_', b'_', b'D', b'W', b'A', b'R', b'F', b'\x00', b'\x00', b'\x00', b'\x00', b'\x00',
  b'\x00', b'\x00', b'\x00', b'\x00',
])

///|
/// The section name `__debug_line`, NUL-padded to 16 bytes.
let sectname_debug_line : Bytes = Bytes::from_array([
  b'_', b'_', b'd', b'e', b'b', b'u', b'g', b'_', b'l', b'i', b'n', b'e', b'\x00',
  b'\x00', b'\x00', b'\x00',
])

///|
/// Builds a thin Mach-O whose only content is a `__DWARF,__debug_line` section
/// holding `program`.
///
/// A hand-written program is the only way to reach the boundary between a
/// standard and a special opcode: a compiler never emits the byte equal to
/// `opcode_base` unless it needs the one-line advance that encoding produces,
/// and neither of this project's dSYMs happens to contain it. Without a
/// constructed program, changing `>=` to `>` in the dispatcher is invisible.
fn image_with_line_program(program : Bytes) -> MachSlice raise {
  let seg_cmd_size = 72 + 80 // LC_SEGMENT_64 plus one section
  let header_size = 32
  let sizeofcmds = seg_cmd_size
  let section_off = header_size + sizeofcmds
  let vmaddr = 0x1_0000_0000L
  let buf = Buffer()
  buf.write_uint_le(0xFEED_FACF) // MH_MAGIC_64
  buf.write_int_le(0x0100_000C) // CPU_TYPE_ARM64
  buf.write_int_le(0)
  buf.write_uint_le(0x0A) // MH_DSYM
  buf.write_uint_le(1U) // ncmds
  buf.write_uint_le(sizeofcmds.reinterpret_as_uint())
  buf.write_uint_le(0)
  buf.write_uint_le(0)
  // LC_SEGMENT_64
  buf.write_uint_le(0x19U)
  buf.write_uint_le(seg_cmd_size.reinterpret_as_uint())
  buf.write_bytes(segname_dwarf)
  buf.write_uint64_le(vmaddr.reinterpret_as_uint64())
  buf.write_uint64_le(0x1000UL) // vmsize
  buf.write_uint64_le(section_off.to_int64().reinterpret_as_uint64()) // fileoff
  buf.write_uint64_le(program.length().to_int64().reinterpret_as_uint64()) // filesize
  buf.write_int_le(7) // maxprot rwx
  buf.write_int_le(7) // initprot
  buf.write_uint_le(1U) // nsects
  buf.write_uint_le(0) // flags
  // section_64: __debug_line in __DWARF
  buf.write_bytes(sectname_debug_line)
  buf.write_bytes(segname_dwarf)
  buf.write_uint64_le(vmaddr.reinterpret_as_uint64()) // addr
  buf.write_uint64_le(program.length().to_int64().reinterpret_as_uint64()) // size
  buf.write_uint_le(section_off.reinterpret_as_uint()) // offset
  buf.write_uint_le(0) // align
  buf.write_uint_le(0) // reloff
  buf.write_uint_le(0) // nreloc
  buf.write_uint_le(0) // flags
  buf.write_uint_le(0) // reserved1
  buf.write_uint_le(0) // reserved2
  buf.write_uint_le(0) // reserved3
  for i in 0..<program.length() {
    buf.write_byte(program.at(i))
  }
  match parse(buf.to_bytes()) {
    Thin(s) => s
    Fat(_) => fail("expected thin")
  }
}

///|
/// A DWARF 4 line program with `opcode_base` 13 and two special opcodes, one of
/// which is exactly 13.
///
/// `opcode_base` 13 means the standard opcodes are 1..12. The byte 13 is the
/// first *special* opcode, and it means "advance one line, no address change"
/// because `line_base` is -5 and `line_range` 14: adjusted 0, so line += -5 is
/// wrong; adjusted 5 would be line += 0. Both readings are legal encodings, and
/// which one applies is decided by whether the dispatcher tests `>=` or `>`.
fn program_with_opcode_base() -> Bytes {
  // After unit_length: version, header_length, the six scalar prologue
  // fields, twelve standard-opcode lengths, then the string lists.
  let body = Buffer()
  // One include directory and one file name, each NUL-terminated, the two
  // lists separated and terminated by NUL as DWARF 2-4 requires.
  body.write_byte(b'.')
  body.write_byte(b'/')
  body.write_byte(b'\x00')
  body.write_byte(b'\x00')
  body.write_byte(b'a')
  body.write_byte(b'.')
  body.write_byte(b'c')
  body.write_byte(b'\x00')
  body.write_byte(b'\x00')
  // The opcode stream: advance the address by 16, emit one row with the
  // special opcode whose value equals opcode_base, then end the sequence.
  let ops = Buffer()
  ops.write_byte(b'\x02') // DW_LNS_advance_pc
  ops.write_byte(b'\x10') // uleb 16
  ops.write_byte(b'\x0d') // special opcode 13 == opcode_base
  ops.write_byte(b'\x00') // DW_LNE_end_sequence
  ops.write_byte(b'\x01') // length
  ops.write_byte(b'\x01') // extended opcode 1
  // header_length is measured from the byte after itself, i.e. it covers the
  // six scalar fields, the twelve standard lengths, and the two string lists.
  let prologue = body.length() + 6 + 12
  let out = Buffer()
  // unit_length, written after everything else is sized.
  let tail_len = 2 + 4 + prologue + ops.length()
  out.write_uint_le(tail_len.reinterpret_as_uint())
  out.write_uint16_le(4) // version
  out.write_uint_le(prologue.reinterpret_as_uint()) // header_length
  out.write_byte(b'\x01') // min_inst_length
  out.write_byte(b'\x01') // max_ops_per_inst
  out.write_byte(b'\x01') // default_is_stmt
  out.write_byte(b'\xfb') // line_base -5
  out.write_byte(b'\x0e') // line_range 14
  out.write_byte(b'\x0d') // opcode_base 13
  for _ in 1..<13 {
    out.write_byte(b'\x00') // standard opcode operand counts
  }
  out.write_bytes(body.to_bytes())
  out.write_bytes(ops.to_bytes())
  out.to_bytes()
}

///|
test "boundary: the byte equal to opcode_base is a special opcode" {
  // `opcode_base` is the first special opcode, so the dispatcher must compare
  // with `>=`. Testing `>` sends that one byte down the standard-opcode path,
  // where it is read as an opcode 13 — which has no case, so it is skipped
  // silently and the row it should have emitted never appears.
  //
  // Neither committed dSYM contains this byte, so only a constructed program
  // can reach it. That is why this test builds one: a change that flips the
  // comparison passed the whole suite before it existed.
  let program = program_with_opcode_base()
  let slice = image_with_line_program(program)
  let tables = line_tables(slice, comp_dir="/c")
  if tables.length() != 1 {
    fail("expected one line program, got \{tables.length()}")
  }
  let t = tables[0]
  inspect(t.version.to_int64(), content="4")
  // The program advances the address by 0x10, emits a row at the special
  // opcode, then ends the sequence. Two live rows plus the end-of-sequence row.
  let live : Array[LineRow] = []
  for r in t.rows {
    if !r.end_sequence {
      live.push(r)
    }
  }
  inspect(live.length(), content="1")
  inspect(live[0].address, content="16")
}
