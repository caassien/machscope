// The dyld export trie.
//
// A modern Mach-O does not store exported symbols in a flat table. It stores
// them in a radix trie: each node is a prefix of the remaining name, followed
// by a list of children and, for nodes that end a symbol, a zero-terminated
// entry carrying the flags and the address. Reconstructing the symbol list
// means walking the trie and concatenating prefixes.
//
// A stripped binary keeps exported symbols only here, not in `LC_SYMTAB`.

///|
/// `LC_DYLD_INFO` and `LC_DYLD_INFO_ONLY`.
pub const LC_DYLD_INFO : UInt32 = 0x22

///|
/// 64-bit variant.
pub const LC_DYLD_INFO_ONLY : UInt32 = 0x8000_0022

///|
/// `LC_DYLD_EXPORTS_TRIE`: names the export trie directly.
pub const LC_DYLD_EXPORTS_TRIE : UInt32 = 0x8000_0033

///|
/// `EXPORT_SYMBOL_FLAGS_KIND_MASK`: the low two bits select the kind.
pub const EXPORT_KIND_MASK : UInt64 = 0x03

///|
/// `EXPORT_SYMBOL_FLAGS_KIND_REGULAR`: the address is the symbol's address.
pub const EXPORT_KIND_REGULAR : UInt64 = 0x00

///|
/// `EXPORT_SYMBOL_FLAGS_KIND_THREAD_LOCAL`.
pub const EXPORT_KIND_THREAD_LOCAL : UInt64 = 0x01

///|
/// `EXPORT_SYMBOL_FLAGS_KIND_ABSOLUTE`: the value is not an address.
pub const EXPORT_KIND_ABSOLUTE : UInt64 = 0x02

///|
/// `EXPORT_SYMBOL_FLAGS_WEAK_DEFINITION`: a weak definition can be replaced.
pub const EXPORT_FLAG_WEAK : UInt64 = 0x04

///|
/// `EXPORT_SYMBOL_FLAGS_REEXPORT`: the symbol is re-exported from a library.
pub const EXPORT_FLAG_REEXPORT : UInt64 = 0x08

///|
/// `EXPORT_SYMBOL_FLAGS_STUB_AND_RESOLVER`.
pub const EXPORT_FLAG_STUB_AND_RESOLVER : UInt64 = 0x10

///|
/// One symbol exported by the image.
pub(all) struct Export {
  /// The full symbol name, reconstructed from the trie's prefixes.
  name : String
  /// `flags` for the regular and thread-local kinds: the address. For a
  /// re-export it is the library ordinal instead.
  address : UInt64
  /// The flags word, kept whole so callers can test any bit.
  flags : UInt64
  /// For a re-export, the name the symbol has in its own library.
  original_name : String
}

///|
/// The kind of an export, from the low bits of its flags.
pub fn Export::kind(self : Export) -> UInt64 {
  self.flags & EXPORT_KIND_MASK
}

///|
/// Whether the export is re-exported from another library.
pub fn Export::is_reexport(self : Export) -> Bool {
  (self.flags & EXPORT_FLAG_REEXPORT) != 0UL
}

///|
/// Whether the export is a weak definition.
pub fn Export::is_weak(self : Export) -> Bool {
  (self.flags & EXPORT_FLAG_WEAK) != 0UL
}

///|
/// Where the export trie lives inside the file.
pub(all) struct ExportTrieRegion {
  /// Absolute file offset of the trie.
  offset : Int64
  /// Byte length of the trie.
  size : Int64
}

///|
/// Finds the export trie, preferring `LC_DYLD_EXPORTS_TRIE` and falling back to
/// the export fields of `LC_DYLD_INFO`.
///
/// Both forms appear in the wild: the standalone command was added later, and
/// older linkers put the same bytes in `LC_DYLD_INFO` only.
pub fn export_trie(slice : MachSlice) -> ExportTrieRegion? raise MachscopeError {
  for cmd in slice.commands {
    if cmd.cmd == LC_DYLD_EXPORTS_TRIE {
      let body = command_payload(slice, cmd)
      let cur = Cursor::{ pos: body.start, endian: slice.header.kind.endian(), }
      let (off, cur) = body.read_u32(cur)
      let (size, _) = body.read_u32(cur)
      // `fileoff` in a load command is relative to the image, so a fat slice
      // has to add its own base. Thin images have base 0 and are unaffected.
      let region = ExportTrieRegion::{
        offset: slice.bounds.start + off.to_int64(),
        size: size.to_int64(),
      }
      slice.bounds.require(region.offset, region.size, "export trie")
      return Some(region)
    }
  }
  for cmd in slice.commands {
    if cmd.cmd == LC_DYLD_INFO || cmd.cmd == LC_DYLD_INFO_ONLY {
      let body = command_payload(slice, cmd)
      let cur = Cursor::{ pos: body.start, endian: slice.header.kind.endian(), }
      // Ten 32-bit words in order: rebase_off, rebase_size, bind_off,
      // bind_size, weak_bind_off, weak_bind_size, lazy_bind_off,
      // lazy_bind_size, export_off, export_size. The export pair is last, so
      // skip the four rebase and bind pairs that precede it.
      let mut c = cur
      for _ in 0..<8 {
        let (_, c1) = body.read_u32(c)
        c = c1
      }
      let (off, c) = body.read_u32(c)
      let (size, _) = body.read_u32(c)
      if size == 0U {
        return None
      }
      // `fileoff` in a load command is relative to the image, so a fat slice
      // has to add its own base. Thin images have base 0 and are unaffected.
      let region = ExportTrieRegion::{
        offset: slice.bounds.start + off.to_int64(),
        size: size.to_int64(),
      }
      slice.bounds.require(region.offset, region.size, "export trie")
      return Some(region)
    }
  }
  None
}

///|
/// Reads the symbols from an export trie.
///
/// The walk uses an explicit stack so a corrupt trie cannot exhaust the call
/// stack.
pub fn exports(slice : MachSlice) -> Array[Export] raise MachscopeError {
  let region = match export_trie(slice) {
    Some(r) => r
    None => return []
  }
  let b = slice.bounds
  let out : Array[Export] = []
  // Each stack entry is a node offset paired with the prefix that reaches it.
  let stack : Array[(Int64, String)] = [(region.offset, "")]
  let mut visited = 0
  while stack.length() > 0 {
    let entry = stack.pop().unwrap()
    let (node, prefix) = entry
    visited = visited + 1
    if visited > 100_000 {
      raise LimitExceeded(what="export trie nodes", limit=100_000L)
    }
    let rel = node - region.offset
    if rel < 0L || rel >= region.size {
      raise OutOfBounds(
        what="export trie node",
        offset=node,
        size=1L,
        limit=region.offset + region.size,
      )
    }
    let mut cur = Cursor::{ pos: node, endian: Endian::Little, }
    let (terminal_size, c1) = read_uleb128(b, cur)
    cur = c1
    let terminal_start = cur.pos
    if terminal_size != 0UL {
      let (flags, c2) = read_uleb128(b, cur)
      cur = c2
      let mut address = 0UL
      let mut original_name = ""
      let mut after = c2
      if (flags & EXPORT_FLAG_REEXPORT) != 0UL {
        // Re-export: the ordinal of the source library, then its name.
        let (ordinal, c3) = read_uleb128(b, after)
        after = c3
        if ordinal != 0UL {
          let (name, c4) = read_c_string_z(b, after.pos)
          original_name = name
          after = c4
        }
        address = ordinal
      } else {
        let (addr, c3) = read_uleb128(b, after)
        after = c3
        address = addr
        if (flags & EXPORT_FLAG_STUB_AND_RESOLVER) != 0UL {
          let (_, c4) = read_uleb128(b, after)
          after = c4
        }
      }
      let _ = after
      // Only the regular and thread-local kinds carry an address worth
      // reporting; an absolute export's value is a constant, not a location.
      out.push(Export::{ name: prefix, address, flags, original_name, })
    }
    // The terminal entry's declared size covers everything it used, so the
    // child list starts a fixed distance after it. Using the declared size
    // rather than this decoder's own cursor means an unrecognised flag layout
    // still leaves the children readable.
    // Skip whatever the terminal entry declared, so that a flag layout this
    // version does not decode still leaves the child list at the right place.
    let children_at = terminal_start + terminal_size.reinterpret_as_int64()
    let c0 = Cursor::{ pos: children_at, endian: Endian::Little, }
    let (child_count, c5) = b.read_u8(c0)
    let mut cc = c5
    let n_children = child_count.reinterpret_as_int()
    for _ in 0..<n_children {
      let (edge, c6) = read_c_string_z(b, cc.pos)
      let (child_rel, c7) = read_uleb128(b, c6)
      stack.push(
        (region.offset + child_rel.reinterpret_as_int64(), prefix + edge),
      )
      cc = c7
    }
  }
  out
}

///|
/// Reads a NUL-terminated string that must not run past the buffer.
fn read_c_string_z(
  b : Bounds,
  at : Int64,
) -> (String, Cursor) raise MachscopeError {
  let buf = StringBuilder()
  let mut pos = at
  let mut done = false
  while !done {
    b.require(pos, 1L, "export trie edge")
    let byte = b.bytes.at(pos.to_int())
    pos = pos + 1L
    if byte.to_int() == 0 {
      done = true
    } else {
      buf.write_char(byte.to_char())
    }
  }
  (buf.to_string(), Cursor::{ pos, endian: Endian::Little, })
}
