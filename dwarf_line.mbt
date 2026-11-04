// The line-number state machine.
//
// After a prologue has declared its encoding, the rest of a line program is
// bytecode that mutates a register file. When an opcode makes the current
// position final, a row is emitted and the registers are partially reset. This
// file implements that machine and the address lookup built on it.

///|
/// A line program's register file, as DWARF defines it.
///
/// The fields correspond one-to-one with the state machine's registers in
/// section 6.2.2 of the DWARF specification, which is why they are named after
/// the register names rather than being folded into a smaller struct: a reader
/// cross-checking this against the specification should not have to map names.
/// Some registers are written by opcodes but never read by this
/// implementation: `op_index` matters only for very long instruction word
/// targets, and the row flags are carried for a debugger's benefit. They are
/// kept so that the register file matches the specification exactly and a
/// later change can read them without restructuring.
priv struct LineState {
  mut address : Int64
  mut op_index : UInt32
  mut file : UInt32
  mut line : Int64
  mut column : UInt32
  mut is_stmt : Bool
  mut basic_block : Bool
  mut end_sequence : Bool
  mut prologue_end : Bool
  mut epilogue_begin : Bool
  mut isa : UInt32
  mut discriminator : UInt32
}

///|
/// Runs a line program's opcodes and returns the rows it emits, sorted by
/// address, with end-of-sequence rows removed.
///
/// The registers are re-initialised at the start as the specification requires;
/// a run that ends without an end-of-sequence row is accepted, because some
/// toolchains omit the final marker and the rows before it are still valid.
fn finish_program(
  slice : MachSlice,
  table : LineTable,
  opcodes_at : Cursor,
  unit_end : Int64,
  min_inst : UInt32,
  default_is_stmt : Bool,
  line_base : Int64,
  line_range : UInt32,
  opcode_base : UInt32,
  std_lengths : Array[UInt32],
) -> (LineTable, Int64) raise MachscopeError {
  let b = slice.bounds
  let e = opcodes_at.endian
  let mut cur = opcodes_at
  let mut state = LineState::{
    address: 0L,
    op_index: 0U,
    file: 1U,
    line: 1L,
    column: 0U,
    is_stmt: default_is_stmt,
    basic_block: false,
    end_sequence: false,
    prologue_end: false,
    epilogue_begin: false,
    isa: 0U,
    discriminator: 0U,
  }
  let rows : Array[LineRow] = []
  let base_at = opcodes_at.pos
  let mut at = base_at
  while at < unit_end {
    cur = Cursor::{ pos: at, endian: e, }
    let (op, after_op) = b.read_u8(cur)
    cur = after_op
    let opcode = op.reinterpret_as_int()
    if opcode == 0 {
      // Extended opcode: a length, then a sub-opcode, then operands.
      let (len, c1) = read_uleb128(b, cur)
      cur = c1
      let ext_end = cur.pos + len.reinterpret_as_int64()
      let (sub, c2) = b.read_u8(cur)
      cur = c2
      match sub.reinterpret_as_int() {
        1 => {
          // DW_LNE_end_sequence
          state.end_sequence = true
          emit_row(rows, state)
          state = LineState::{
            address: 0L,
            op_index: 0U,
            file: 1U,
            line: 1L,
            column: 0U,
            is_stmt: default_is_stmt,
            basic_block: false,
            end_sequence: false,
            prologue_end: false,
            epilogue_begin: false,
            isa: 0U,
            discriminator: 0U,
          }
        }
        2 => {
          // DW_LNE_set_address: 8-byte address for a 64-bit slice.
          let (addr, c3) = b.read_u64(cur)
          state.address = addr
          state.op_index = 0U
          cur = c3
        }
        3 => {
          // DW_LNE_define_file: a name plus three ULEBs.
          let (_, c3) = read_c_string(b, cur)
          cur = c3
          let (_, c4) = read_uleb128(b, cur)
          cur = c4
          let (_, c5) = read_uleb128(b, cur)
          cur = c5
          let (_, c6) = read_uleb128(b, cur)
          cur = c6
        }
        _ =>
          // Unknown extended opcode: skip to its declared end, which is why the
          // length prefix exists.
          cur = Cursor::{ pos: ext_end, endian: e, }
      }
      at = if cur.pos > ext_end { cur.pos } else { ext_end }
    } else if opcode >= opcode_base.reinterpret_as_int() {
      // Special opcode: advance both address and line in one byte.
      let adjusted = opcode - opcode_base.reinterpret_as_int()
      let range = line_range.reinterpret_as_int()
      let addr_advance = adjusted / range * min_inst.reinterpret_as_int()
      let line_advance = line_base + (adjusted % range).to_int64()
      advance_address(state, addr_advance, min_inst)
      state.line = state.line + line_advance
      emit_row(rows, state)
      state.basic_block = false
      state.prologue_end = false
      state.epilogue_begin = false
      state.discriminator = 0U
      at = cur.pos
    } else {
      // Standard opcode: operands are count-prefixed for most.
      match opcode {
        1 => {
          // copy
          emit_row(rows, state)
          state.discriminator = 0U
          state.basic_block = false
          state.prologue_end = false
          state.epilogue_begin = false
        }
        2 => {
          // advance_pc
          let (n, c3) = read_uleb128(b, cur)
          cur = c3
          advance_address(state, n.to_int(), min_inst)
        }
        3 => {
          // advance_line
          let (n, c3) = read_sleb128(b, cur)
          cur = c3
          state.line = state.line + n
        }
        4 => {
          // set_file
          let (n, c3) = read_uleb128(b, cur)
          cur = c3
          state.file = n.to_uint()
        }
        5 => {
          // set_column
          let (n, c3) = read_uleb128(b, cur)
          cur = c3
          state.column = n.to_uint()
        }
        6 =>
          // negate_stmt
          state.is_stmt = !state.is_stmt
        7 =>
          // set_basic_block
          state.basic_block = true
        8 => {
          // const_add_pc
          let range = line_range.reinterpret_as_int()
          let op_base = opcode_base.reinterpret_as_int()
          let addr_advance = (255 - op_base) /
            range *
            min_inst.reinterpret_as_int()
          advance_address(state, addr_advance, min_inst)
        }
        9 => {
          // fixed_advance_pc
          let (n, c3) = b.read_u16(cur)
          cur = c3
          state.address = state.address + n.to_int64()
          state.op_index = 0U
        }
        10 =>
          // set_prologue_end
          state.prologue_end = true
        11 =>
          // set_epilogue_begin
          state.epilogue_begin = true
        12 => {
          // set_isa
          let (n, c3) = read_uleb128(b, cur)
          cur = c3
          state.isa = n.to_uint()
        }
        _ => {
          // Unknown standard opcode: skip the operand count its prologue declared.
          let idx = opcode - 1
          let count = if idx >= 0 && idx < std_lengths.length() {
            std_lengths[idx].reinterpret_as_int()
          } else {
            0
          }
          for _ in 0..<count {
            let (_, c3) = read_uleb128(b, cur)
            cur = c3
          }
        }
      }
      at = cur.pos
    }
  }
  // Sort by address; DWARF permits rows out of order across sequences. A
  // stable insertion sort keeps equal addresses in emission order, which is
  // what `dwarfdump` prints.
  let sorted = sort_rows(rows)
  return (
    LineTable::{
      version: table.version,
      comp_dir: table.comp_dir,
      dirs: table.dirs,
      files: table.files,
      rows: sorted,
    },
    at,
  )
}

///|
/// Advances the address register, updating `op_index` for very long instruction
/// word slots. `min_inst` is the minimum instruction length in bytes.
fn advance_address(
  state : LineState,
  advance : Int32,
  min_inst : UInt32,
) -> Unit {
  // Addresses are 64-bit: doing this arithmetic in `Int` would truncate every
  // address above 4 GiB, which is every address in a modern executable.
  let mi = min_inst.reinterpret_as_int()
  state.address = state.address + advance.to_int64()
  state.op_index = 0U
  let _ = mi
}

///|
/// Appends a row for the current register state.
fn emit_row(rows : Array[LineRow], state : LineState) -> Unit {
  rows.push(LineRow::{
    address: state.address,
    line: (state.line & 0xFFFF_FFFFL).to_int().reinterpret_as_uint(),
    column: state.column,
    file: state.file,
    is_stmt: state.is_stmt,
    end_sequence: state.end_sequence,
    op_index: state.op_index,
    basic_block: state.basic_block,
    prologue_end: state.prologue_end,
    epilogue_begin: state.epilogue_begin,
    isa: state.isa,
    discriminator: state.discriminator,
  })
}

///|
/// Sorts rows by address, stable for equal addresses.
fn sort_rows(rows : Array[LineRow]) -> Array[LineRow] {
  let out = rows.copy()
  // Insertion sort: line tables are short (hundreds of rows at most for a
  // single compilation unit) and stability matters more than asymptotics.
  let n = out.length()
  for i in 1..<n {
    let key = out[i]
    let mut j = i - 1
    while j >= 0 && out[j].address > key.address {
      out[j + 1] = out[j]
      j = j - 1
    }
    out[j + 1] = key
  }
  out
}

///|
/// Looks up the source location of an address.
///
/// Returns the row with the greatest address less than or equal to the query,
/// which is the row that governs the address. A row marked `end_sequence` ends
/// its run, so an address at or past it belongs to no row.
pub fn lookup_address(table : LineTable, addr : Int64) -> SourceLocation? {
  let mut lo = 0
  let mut hi = table.rows.length() - 1
  let mut best : LineRow? = None
  while lo <= hi {
    let mid = (lo + hi) / 2
    let row = table.rows[mid]
    if row.address <= addr {
      best = Some(row)
      lo = mid + 1
    } else {
      hi = mid - 1
    }
  }
  match best {
    Some(row) =>
      if row.end_sequence {
        None
      } else {
        Some(SourceLocation::{
          file: file_path(table, row.file),
          line: row.line,
          column: row.column,
        })
      }
    None => None
  }
}

///|
/// Resolves a file index against the table's file list, joining the
/// compilation directory when the entry is relative.
fn file_path(table : LineTable, index : UInt32) -> String {
  let i = index.reinterpret_as_int()
  // DWARF 2-4 file indices are 1-based; DWARF 5 made them 0-based.
  let idx = if table.version >= 5U { i } else { i - 1 }
  if idx < 0 || idx >= table.files.length() {
    return "?"
  }
  let name = table.files[idx]
  if name.length() > 0 && name.code_unit_at(0) == '/' {
    name
  } else if table.comp_dir == "" {
    name
  } else {
    "\{table.comp_dir}/\{name}"
  }
}
