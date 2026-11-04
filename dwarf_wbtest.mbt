// Differential tests for DWARF line tables, against `dwarfdump --debug-line`.
//
// `sample.dsym` is a dSYM produced by `clang -g` and `dsymutil` from the
// three-line `sample.c` checked in beside it. dwarfdump prints the prologue
// fields and every row; the assertions below are copied from its output.

///|
/// The single line table of the sample dSYM.
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
  inspect(t.dirs[0], content="/tmp")
  inspect(t.files[0], content="t.c")
}

///|
test "oracle: the row addresses match dwarfdump" {
  // dwarfdump --debug-line lists, in order (end_sequence removed):
  //   0x100000460 line 2, 0x100000468 line 2, 0x10000046c line 2,
  //   0x100000470 line 2, 0x100000478 line 3, 0x100000490 line 3,
  //   0x100000498 line 3, 0x1000004b4 line 3, 0x1000004c0 line 3 (end_sequence)
  let t = sample_table()
  // The end-of-sequence row is dropped from `rows` and kept separately.
  let addrs : Array[String] = []
  for row in t.rows {
    if !row.end_sequence {
      addrs.push(row.address.to_string())
    }
  }
  inspect(
    addrs.join(","),
    content="4294968416,4294968424,4294968428,4294968432,4294968440,4294968464,4294968472,4294968500",
  )
}

///|
test "oracle: the line and column fields match dwarfdump" {
  // The first four rows are all line 2; columns are 0, 28, 30, 21.
  let t = sample_table()
  let live : Array[LineRow] = []
  for row in t.rows {
    if !row.end_sequence {
      live.push(row)
    }
  }
  inspect(live[0].line.to_int64(), content="2")
  inspect(live[0].column.to_int64(), content="0")
  inspect(live[1].line.to_int64(), content="2")
  inspect(live[1].column.to_int64(), content="28")
  inspect(live[2].line.to_int64(), content="2")
  inspect(live[2].column.to_int64(), content="30")
  inspect(live[3].line.to_int64(), content="2")
  inspect(live[3].column.to_int64(), content="21")
  // The helper function's body is line 3.
  inspect(live[4].line.to_int64(), content="3")
  inspect(live[4].column.to_int64(), content="0")
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
  // 0x100000468 is `printf`'s argument evaluation on line 2, column 28.
  let t = sample_table()
  let loc = match lookup_address(t, 0x1_0000_0468L) {
    Some(l) => l
    None => fail("expected a location")
  }
  inspect(loc.line.to_int64(), content="2")
  inspect(loc.column.to_int64(), content="28")
  inspect(loc.file, content="/tmp/t.c")
}

///|
test "lookup: an address between rows uses the row that governs it" {
  // 0x10000046a sits between the row at ...468 and the one at ...46c, so it
  // must resolve to the ...468 row, not to the following one.
  let t = sample_table()
  let loc = match lookup_address(t, 0x1_0000_046AL) {
    Some(l) => l
    None => fail("expected a location")
  }
  inspect(loc.line.to_int64(), content="2")
  inspect(loc.column.to_int64(), content="28")
}

///|
test "lookup: an address before the first row has no location" {
  let t = sample_table()
  inspect(lookup_address(t, 0x100L) is None, content="true")
}

///|
test "lookup: the helper function's address resolves to line 3" {
  // 0x100000490 is the prologue_end of `helper`, on line 3.
  let t = sample_table()
  let loc = match lookup_address(t, 0x1_0000_0490L) {
    Some(l) => l
    None => fail("expected a location")
  }
  inspect(loc.line.to_int64(), content="3")
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
