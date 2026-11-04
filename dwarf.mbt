// DWARF line-number programs: the mapping from a code address to the source
// file and line it came from.
//
// This is the part of DWARF that turns a crash report's `0x1000046c` into
// `t.c:2:30`, and it is the only part that is both small enough to implement
// well in a month and useful on its own. The `.debug_info` tree, expression
// evaluation and type reconstruction are out of scope; `.debug_line` is not,
// because it has a self-contained state machine that is fully specified and
// fully verifiable.
//
// A line program is a bytecode: a prologue declaring the encoding, then
// opcodes that advance a register file, emitting a row whenever a position is
// final. Rows are sorted by address at the end, and an address is looked up in
// that sorted table.

///|
/// One decoded row of a line table: an address together with the source
/// position that applies from it until the next row.
pub(all) struct LineRow {
  /// Address the row applies from.
  address : Int64
  /// 1-based source line; 0 means "no line", which DWARF uses for compiler
  /// generated code that has no source position.
  line : UInt32
  /// 1-based column, or 0 when unknown.
  column : UInt32
  /// Index into the line table's file list.
  file : UInt32
  /// `is_stmt`: the address is a statement boundary, i.e. a place a debugger
  /// should stop.
  is_stmt : Bool
  /// `end_sequence`: this row ends a contiguous run of addresses and introduces
  /// no code of its own.
  end_sequence : Bool
  /// `op_index`: which operation of a very long instruction word this address
  /// refers to. Zero on every fixed-width instruction set.
  op_index : UInt32
  /// `basic_block`: the address starts a basic block.
  basic_block : Bool
  /// `prologue_end`: the address is the end of the function's prologue, a
  /// place a debugger breaks at when stepping into a frame.
  prologue_end : Bool
  /// `epilogue_begin`: the address starts the function's epilogue.
  epilogue_begin : Bool
  /// `isa`: the instruction set the address belongs to, for targets with more
  /// than one. Zero on every Apple platform.
  isa : UInt32
  /// `discriminator`: distinguishes blocks on the same source line, which a
  /// coverage tool uses to tell them apart.
  discriminator : UInt32
}

///|
/// What an address resolved to: a file, a line and a column.
pub(all) struct SourceLocation {
  /// Path of the source file, with the compilation directory applied.
  file : String
  /// 1-based line.
  line : UInt32
  /// 1-based column, or 0 when unknown.
  column : UInt32
}

///|
/// The state of a line program that persists across file and directory lists.
///
/// DWARF 5 changed how the file list is encoded; both the version 2-4 list of
/// NUL-terminated names and the version 5 list of file entries with directory
/// indices are decoded, because a dSYM in the wild may be either.
pub(all) struct LineTable {
  /// `DWARF` version of the program that produced these rows.
  version : UInt32
  /// The compilation directory, used to make file paths absolute.
  comp_dir : String
  /// Include directories, indexed by the file list.
  dirs : Array[String]
  /// File names, in the order the file index numbers them.
  files : Array[String]
  /// Rows sorted by address, with end-of-sequence rows removed.
  rows : Array[LineRow]
}

///|
/// The `.debug_line` section of a slice.
pub fn debug_line_section(slice : MachSlice) -> Section? raise MachscopeError {
  let segs = segments(slice)
  find_section(segs, "__DWARF", "__debug_line")
}

///|
/// Parses every line program in a `.debug_line` section.
///
/// `comp_dir` comes from the caller because in DWARF 2-4 it lives in the
/// `.debug_info` compilation unit, not in the line prologue; a dSYM reader
/// that has not parsed `.debug_info` can still resolve paths relative to it.
pub fn line_tables(
  slice : MachSlice,
  comp_dir~ : String = "",
) -> Array[LineTable] raise MachscopeError {
  let out : Array[LineTable] = []
  let sec = match debug_line_section(slice) {
    Some(s) => s
    None => return []
  }
  let start = sec.file_offset.to_int64()
  let end = start + sec.size
  slice.bounds.require(start, sec.size, "__debug_line")
  let mut at = start
  while at < end {
    let (table, next) = parse_line_program(slice, at, end, comp_dir)
    out.push(table)
    at = next
  }
  out
}

///|
/// Parses one line program starting at `at`, returning the table and the offset
/// just past the program.
fn parse_line_program(
  slice : MachSlice,
  at : Int64,
  end : Int64,
  comp_dir : String,
) -> (LineTable, Int64) raise MachscopeError {
  let b = slice.bounds
  let e = Endian::Little // DWARF in a Mach-O slice follows the slice's order
  let c = Cursor::{ pos: at, endian: e, }
  let (unit_length, c) = b.read_u32(c)
  if unit_length == 0U {
    // Padding at the end of the section.
    return (
      LineTable::{ version: 0, comp_dir, dirs: [], files: [], rows: [], },
      end,
    )
  }
  let unit_end = c.pos + unit_length.to_int64()
  if unit_end > end {
    raise OutOfBounds(
      what="line program",
      offset=at,
      size=unit_length.to_int64(),
      limit=end,
    )
  }
  let (version, c) = b.read_u16(c)
  if version >= 5U {
    let (address_size, c) = b.read_u8(c)
    let (seg_size, c) = b.read_u8(c)
    let (_, c) = b.read_u32(c) // header_length: the prologue bounds
    let _ = match seg_size {
      0U => ()
      _ => raise Unsupported(what="DWARF segment selectors")
    }
    let _ = address_size
    // DWARF 5 prologue: min_inst_length, max_ops, default_is_stmt, line_base,
    // line_range, opcode_base, then operand counts.
    let (min_inst, c) = b.read_u8(c)
    let (_, c) = b.read_u8(c) // max_ops_per_inst
    let (default_is_stmt, c) = b.read_u8(c)
    let (line_base, c) = b.read_i8(c)
    let (line_range, c) = b.read_u8(c)
    let (opcode_base, c) = b.read_u8(c)
    let std_lengths : Array[UInt32] = []
    let mut cur = c
    for _ in 1..<opcode_base.reinterpret_as_int() {
      let (n, next) = b.read_u8(cur)
      std_lengths.push(n)
      cur = next
    }
    // DWARF 5 replaced the bare string lists with a format description: a
    // count of (content type, form) pairs, then a count of entries, then the
    // entries encoded in those forms. Decoding needs `.debug_line_str`, which
    // `line_strp` offsets refer to.
    let line_str = debug_line_str_section(slice)
    let (dirs, cur) = read_dir_table(b, cur, line_str)
    let (files, cur) = read_file_table(b, cur, line_str)
    return finish_program(
      slice,
      LineTable::{ version, comp_dir, dirs, files, rows: [], },
      cur,
      unit_end,
      min_inst,
      default_is_stmt != 0U,
      line_base,
      line_range,
      opcode_base,
      std_lengths,
    )
  }
  // DWARF 2-4: prologue_length, min_inst_length, ...
  let (header_length, c) = b.read_u32(c)
  let prologue_end = c.pos + header_length.to_int64()
  let (min_inst, c) = b.read_u8(c)
  let (_, c) = b.read_u8(c) // max_ops_per_inst, version 4 only
  let (default_is_stmt, c) = b.read_u8(c)
  let (line_base, c) = b.read_i8(c)
  let (line_range, c) = b.read_u8(c)
  let (opcode_base, c) = b.read_u8(c)
  let std_lengths : Array[UInt32] = []
  let mut cur = c
  for _ in 1..<opcode_base.reinterpret_as_int() {
    let (n, next) = b.read_u8(cur)
    std_lengths.push(n)
    cur = next
  }
  // Include directories, then file names, each NUL-terminated and the list
  // ending with an empty string.
  let (dirs, cur) = read_nul_list(b, cur)
  let (files, cur) = read_nul_list(b, cur)
  let _ = prologue_end
  return finish_program(
    slice,
    LineTable::{ version, comp_dir, dirs, files, rows: [], },
    cur,
    unit_end,
    min_inst,
    default_is_stmt != 0U,
    line_base,
    line_range,
    opcode_base,
    std_lengths,
  )
}

///|
/// The `.debug_line_str` section, which `DW_FORM_line_strp` offsets index.
pub fn debug_line_str_section(
  slice : MachSlice,
) -> Section? raise MachscopeError {
  let segs = segments(slice)
  find_section(segs, "__DWARF", "__debug_line_str")
}

///|
/// One (content type, form) pair from a DWARF 5 table description.
priv struct EntryFormat {
  content : UInt32
  form : UInt32
}

///|
/// `DW_FORM_line_strp`: offset into `.debug_line_str`.
const FORM_LINE_STRP : UInt32 = 0x1F

///|
/// `DW_FORM_string`: a NUL-terminated string inline.
const FORM_STRING : UInt32 = 0x08

///|
/// `DW_FORM_udata`: an unsigned LEB128.
const FORM_UDATA : UInt32 = 0x0F

///|
/// `DW_FORM_data16`: 16 bytes, used for the file's MD5.
const FORM_DATA16 : UInt32 = 0x1E

///|
/// `DW_FORM_data1`.
const FORM_DATA1 : UInt32 = 0x0B

///|
/// `DW_FORM_data2`.
const FORM_DATA2 : UInt32 = 0x05

///|
/// `DW_FORM_data4`.
const FORM_DATA4 : UInt32 = 0x06

///|
/// `DW_FORM_data8`.
const FORM_DATA8 : UInt32 = 0x07

///|
/// Reads a table description: a format count followed by that many
/// (content type, form) pairs, then the entry count.
fn read_table_header(
  b : Bounds,
  start : Cursor,
) -> (Array[EntryFormat], UInt64, Cursor) raise MachscopeError {
  let (format_count, c) = b.read_u8(start)
  let formats : Array[EntryFormat] = []
  let mut cur = c
  for _ in 0..<format_count.reinterpret_as_int() {
    let (content, c1) = read_uleb128(b, cur)
    let (form, c2) = read_uleb128(b, c1)
    formats.push(EntryFormat::{
      content: content.to_uint(),
      form: form.to_uint(),
    })
    cur = c2
  }
  let (count, c3) = read_uleb128(b, cur)
  (formats, count, c3)
}

///|
/// Reads one value of the given form and returns it as a string plus the
/// cursor past it. Forms that are not strings yield "".
fn read_form_string(
  b : Bounds,
  start : Cursor,
  form : UInt32,
  line_str : Section?,
) -> (String, Cursor) raise MachscopeError {
  match form {
    FORM_STRING => read_c_string(b, start)
    FORM_LINE_STRP => {
      let (off, c) = b.read_u32(start)
      let s = match line_str {
        Some(sec) =>
          read_c_string(b, Cursor::{
            pos: sec.file_offset.to_int64() + off.to_int64(),
            endian: start.endian,
          })
        None => ("", Cursor::{ pos: start.pos + 4L, endian: start.endian, })
      }
      let (text, _) = s
      (text, c)
    }
    _ => {
      let (_, c) = skip_form(b, start, form)
      ("", c)
    }
  }
}

///|
/// Skips one value of the given form.
fn skip_form(
  b : Bounds,
  start : Cursor,
  form : UInt32,
) -> (UInt64, Cursor) raise MachscopeError {
  match form {
    FORM_UDATA => read_uleb128(b, start)
    FORM_DATA1 => {
      let (v, c) = b.read_u8(start)
      (v.to_int64().reinterpret_as_uint64(), c)
    }
    FORM_DATA2 => {
      let (v, c) = b.read_u16(start)
      (v.to_int64().reinterpret_as_uint64(), c)
    }
    FORM_DATA4 | FORM_LINE_STRP => {
      let (v, c) = b.read_u32(start)
      (v.to_int64().reinterpret_as_uint64(), c)
    }
    FORM_DATA8 => {
      let (v, c) = b.read_u64(start)
      (v.reinterpret_as_uint64(), c)
    }
    FORM_DATA16 => {
      b.require(start.pos, 16L, "DW_FORM_data16")
      (0UL, Cursor::{ pos: start.pos + 16L, endian: start.endian, })
    }
    FORM_STRING => {
      let (_, c) = read_c_string(b, start)
      (0UL, c)
    }
    _ => raise Unsupported(what="DWARF form")
  }
}

///|
/// Reads the DWARF 5 directory table, returning each directory path.
fn read_dir_table(
  b : Bounds,
  start : Cursor,
  line_str : Section?,
) -> (Array[String], Cursor) raise MachscopeError {
  let (formats, count, after_header) = read_table_header(b, start)
  let out : Array[String] = []
  let mut cur = after_header
  for _ in 0..<count.reinterpret_as_int64().to_int() {
    let mut path = ""
    for f in formats {
      if f.content == 0x1U {
        let (s, c1) = read_form_string(b, cur, f.form, line_str)
        path = s
        cur = c1
      } else {
        let (_, c1) = skip_form(b, cur, f.form)
        cur = c1
      }
    }
    out.push(path)
  }
  (out, cur)
}

///|
/// Reads the DWARF 5 file table, returning each entry's name.
fn read_file_table(
  b : Bounds,
  start : Cursor,
  line_str : Section?,
) -> (Array[String], Cursor) raise MachscopeError {
  let (formats, count, after_header) = read_table_header(b, start)
  let out : Array[String] = []
  let mut cur = after_header
  for _ in 0..<count.reinterpret_as_int64().to_int() {
    let mut name = ""
    for f in formats {
      if f.content == 0x1U {
        let (s, c1) = read_form_string(b, cur, f.form, line_str)
        name = s
        cur = c1
      } else {
        let (_, c1) = skip_form(b, cur, f.form)
        cur = c1
      }
    }
    out.push(name)
  }
  (out, cur)
}

///|
/// Reads a list of NUL-terminated strings ending in an empty string.
fn read_nul_list(b : Bounds, start : Cursor) -> (Array[String], Cursor) {
  let out : Array[String] = []
  let mut cur = start
  let mut done = false
  while !done {
    let (s, next) = read_c_string(b, cur)
    cur = next
    if s == "" {
      done = true
    } else {
      out.push(s)
    }
  }
  (out, cur)
}

///|
/// Reads one NUL-terminated string, returning it and the cursor past its
/// terminator.
fn read_c_string(b : Bounds, start : Cursor) -> (String, Cursor) {
  let buf = StringBuilder()
  let mut at = start.pos
  let mut done = false
  while !done {
    let byte = b.bytes.at(at.to_int())
    at = at + 1L
    if byte.to_int() == 0 {
      done = true
    } else {
      buf.write_char(byte.to_char())
    }
  }
  (buf.to_string(), Cursor::{ pos: at, endian: start.endian, })
}

///|
/// Reads an unsigned LEB128 value.
fn read_uleb128(
  b : Bounds,
  start : Cursor,
) -> (UInt64, Cursor) raise MachscopeError {
  let mut result = 0UL
  let mut shift = 0
  let mut at = start.pos
  let mut done = false
  while !done {
    let (byte, next) = b.read_u8(Cursor::{ pos: at, endian: start.endian, })
    at = next.pos
    let payload = (byte.to_int64() & 0x7FL).reinterpret_as_uint64()
    result = result | (payload << shift)
    if (byte.to_int64() & 0x80L) == 0L {
      done = true
    } else {
      shift = shift + 7
      if shift > 63 {
        raise LimitExceeded(what="ULEB128", limit=63L)
      }
    }
  }
  (result, Cursor::{ pos: at, endian: start.endian, })
}

///|
/// Reads a signed LEB128 value.
fn read_sleb128(
  b : Bounds,
  start : Cursor,
) -> (Int64, Cursor) raise MachscopeError {
  let mut result = 0L
  let mut shift = 0
  let mut at = start.pos
  let mut done = false
  while !done {
    let (byte, next) = b.read_u8(Cursor::{ pos: at, endian: start.endian, })
    at = next.pos
    let raw = byte.reinterpret_as_int().to_int64()
    result = result | ((raw & 0x7FL) << shift)
    shift = shift + 7
    if (raw & 0x80L) == 0L {
      done = true
      if shift < 64 && (raw & 0x40L) != 0L {
        result = result | (0L - (1L << shift))
      }
    } else if shift > 63 {
      raise LimitExceeded(what="SLEB128", limit=63L)
    }
  }
  (result, Cursor::{ pos: at, endian: start.endian, })
}
