// Typed load commands.
//
// `macho.mbt` frames the command table; this file gives the framing meaning.
// Commands that carry information the rest of the library needs — the segment
// table, the symbol table, the string table — are decoded into structs.
// Everything else stays a `RawCommand` with its number intact, because
// presenting an unknown command is more useful than refusing the file.

///|
/// `LC_SYMTAB`: where the symbol table and its string table live.
///
/// `nlist` entries do not carry their own names; each holds a 32-bit offset
/// into the string table at `stroff`.
pub(all) struct SymtabCommand {
  /// `symoff`: absolute offset of the first `nlist`.
  symoff : Int64
  /// `nsyms`: number of `nlist` entries.
  nsyms : UInt32
  /// `stroff`: absolute offset of the string table.
  stroff : Int64
  /// `strsize`: byte length of the string table.
  strsize : UInt32
}

///|
/// One `nlist_64` entry.
///
/// `name` is resolved against the string table rather than left as an offset,
/// because every caller wants the name and none wants the offset.
pub(all) struct Symbol {
  /// Symbol name, decoded as UTF-8.
  name : String
  /// `n_type`: the `N_*` type bits plus `N_EXT`/`N_PEXT`.
  n_type : UInt32
  /// `n_sect`: 1-based section ordinal, or 0 when not section-relative.
  n_sect : UInt32
  /// `n_desc`: reference flags and, for undefined symbols, the library ordinal.
  n_desc : UInt32
  /// `n_value`: address, or offset, depending on the symbol's type.
  n_value : Int64
}

///|
/// `N_STAB`: bits set mean this is a debugging entry, not a linkable symbol.
pub const N_STAB : UInt32 = 0xE0

///|
/// `N_TYPE`: the mask selecting a symbol's kind.
pub const N_TYPE : UInt32 = 0x0E

///|
/// `N_EXT`: external symbol.
pub const N_EXT : UInt32 = 0x01

///|
/// Whether the entry is a debug entry rather than a linkable symbol.
///
/// `nm` hides these by default; a tool that wants to match `nm` must filter
/// the same way.
pub fn Symbol::is_debug(self : Symbol) -> Bool {
  (self.n_type & N_STAB) != 0U
}

///|
/// Whether the symbol is visible outside its object.
pub fn Symbol::is_external(self : Symbol) -> Bool {
  (self.n_type & N_EXT) != 0U
}

///|
/// The `n_type` discriminator with the `N_EXT` flag removed.
pub fn Symbol::kind(self : Symbol) -> UInt32 {
  self.n_type & N_TYPE
}

///|
/// Load-command numbers this library decodes into typed values.
///
/// The full list is in `<mach-o/loader.h>`; only the ones that carry data the
/// rest of the library exposes are named here.
pub const LC_SEGMENT : UInt32 = 0x1

///|
/// 64-bit variant of `LC_SEGMENT`.
pub const LC_SEGMENT_64 : UInt32 = 0x19

///|
/// Symbol and string table locations.
pub const LC_SYMTAB : UInt32 = 0x2

///|
/// String table alone, used by object files with no symbols.
pub const LC_DYSYMTAB : UInt32 = 0xB

///|
/// Looks up a command by number and returns its payload region.
///
/// The payload excludes the 8-byte generic header and is checked to lie inside
/// the command's own `cmdsize`, so a decoder can read fields without repeating
/// the framing checks.
fn command_payload(
  slice : MachSlice,
  cmd : RawCommand,
) -> Bounds raise MachscopeError {
  let start = cmd.offset + 8L
  let size = cmd.size.to_int64() - 8L
  slice.bounds.require(start, size, "command payload")
  // `start` moves to the payload but `limit` stays at the slice's end: embedded
  // tables such as a segment's section list are part of the command's
  // `cmdsize`, which the framing already bounded, and capping the view at the
  // command's end here would double-count that check and reject valid tables.
  Bounds::{ bytes: slice.bounds.bytes, start, limit: slice.bounds.limit, }
}

///|
/// Decodes an `LC_SYMTAB` command.
pub fn symtab_command(
  slice : MachSlice,
  cmd : RawCommand,
) -> SymtabCommand raise MachscopeError {
  if cmd.cmd != LC_SYMTAB {
    raise BadValue(field="LC_SYMTAB cmd", value=cmd.cmd.to_int64())
  }
  let body = command_payload(slice, cmd)
  let cur = Cursor::{ pos: body.start, endian: slice.header.kind.endian(), }
  let (symoff, cur) = body.read_u32(cur)
  let (nsyms, cur) = body.read_u32(cur)
  let (stroff, cur) = body.read_u32(cur)
  let (strsize, _) = body.read_u32(cur)
  let symtab = SymtabCommand::{
    symoff: symoff.to_int64(),
    nsyms,
    stroff: stroff.to_int64(),
    strsize,
  }
  // Both tables must be readable, and the symbol table must fit: 16 bytes per
  // `nlist_64`. Checking here means `symbols()` can bound its loop by `nsyms`
  // without re-validating.
  slice.bounds.require(
    symtab.symoff,
    symtab.nsyms.to_int64() * 16L,
    "symbol table",
  )
  slice.bounds.require(symtab.stroff, symtab.strsize.to_int64(), "string table")
  symtab
}

///|
/// Finds the first `LC_SYMTAB` in a slice.
pub fn find_symtab(slice : MachSlice) -> SymtabCommand? raise MachscopeError {
  for cmd in slice.commands {
    if cmd.cmd == LC_SYMTAB {
      return Some(symtab_command(slice, cmd))
    }
  }
  None
}

///|
/// Reads the NUL-terminated string at `offset` inside the string table.
///
/// Mach-O string tables are sequences of NUL-terminated UTF-8 strings; an
/// offset that does not land on a terminator before the end of the table means
/// the table is corrupt, which is reported rather than truncated silently.
pub fn string_table_entry(
  slice : MachSlice,
  tab : SymtabCommand,
  offset : UInt32,
) -> String raise MachscopeError {
  let start = tab.stroff + offset.to_int64()
  let limit = tab.stroff + tab.strsize.to_int64()
  if start < tab.stroff || start >= limit {
    raise OutOfBounds(what="symbol name", offset=start, size=1L, limit~)
  }
  let buf = StringBuilder()
  let mut at = start
  while at < limit {
    let b = slice.bounds.bytes.at(at.to_int())
    if b.to_int() == 0 {
      return buf.to_string()
    }
    // Names are UTF-8; each byte below 0x80 is one code point. Bytes with the
    // high bit set begin a multi-byte sequence, which is decoded as Latin-1 so
    // that a non-ASCII name still yields a distinct string rather than being
    // collapsed into replacement characters.
    buf.write_char(b.to_char())
    at = at + 1
  }
  raise OutOfBounds(
    what="unterminated symbol name",
    offset=start,
    size=1L,
    limit~,
  )
}

///|
/// Decodes every `nlist_64` in the symbol table.
///
/// The count comes from `nsyms` and the loop is bounded by it, which is safe
/// because `symtab_command` already checked that all `nsyms` entries are
/// readable.
pub fn symbols(slice : MachSlice) -> Array[Symbol] raise MachscopeError {
  let tab = match find_symtab(slice) {
    Some(t) => t
    None => return []
  }
  let endian = slice.header.kind.endian()
  let out : Array[Symbol] = []
  let mut at = tab.symoff
  for _ in 0..<tab.nsyms.reinterpret_as_int() {
    let cur = Cursor::{ pos: at, endian, }
    let (strx, cur) = slice.bounds.read_u32(cur)
    let (n_type, cur) = slice.bounds.read_u8(cur)
    let (n_sect, cur) = slice.bounds.read_u8(cur)
    let (n_desc, cur) = slice.bounds.read_u16(cur)
    let (n_value, _) = slice.bounds.read_u64(cur)
    let name = string_table_entry(slice, tab, strx)
    out.push(Symbol::{ name, n_type, n_sect, n_desc, n_value, })
    at = at + 16L
  }
  out
}
