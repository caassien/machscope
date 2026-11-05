// Chained fixups.
//
// Newer binaries replace the rebase/bind opcode streams with chained fixups:
// each location that needs fixing stores, in its own 64-bit slot, both the
// target and the offset of the next fixup in the chain. The linker writes a
// table describing where each chain starts, and a table of imports naming the
// libraries and symbols that unresolved slots point at.
//
// Reading it answers two questions a static analyser asks: which addresses
// hold a pointer into another image (a bind), and which hold an address inside
// this image (a rebase). The chains live in the mapped sections, not in the
// fixup blob, so a parser that stays inside the blob sees only the index.

///|
/// `LC_DYLD_CHAINED_FIXUPS`.
pub const LC_DYLD_CHAINED_FIXUPS : UInt32 = 0x8000_0034

///|
/// `DYLD_CHAINED_IMPORT`: a 4-bit library ordinal and a 24-bit symbol offset.
pub const CHAINED_IMPORT_FORMAT : UInt32 = 1

///|
/// `DYLD_CHAINED_PTR_64`: a 36-bit target, a bind bit, and the next offset.
pub const CHAINED_PTR_64 : UInt32 = 2

///|
/// `DYLD_CHAINED_PTR_64_OFFSET`: same layout, but the target is a file offset
/// rather than a virtual address.
pub const CHAINED_PTR_64_OFFSET : UInt32 = 6

///|
/// `DYLD_CHAINED_PTR_ARM64E`.
pub const CHAINED_PTR_ARM64E : UInt32 = 1

///|
/// `DYLD_CHAINED_PTR_ARM64E_USERLAND`.
pub const CHAINED_PTR_ARM64E_USERLAND : UInt32 = 9

///|
/// One import: a symbol, the library it comes from, and how weakly.
pub(all) struct ChainedImport {
  /// Index into the fixup blob's symbol pool.
  name_offset : UInt32
  /// The resolved symbol name.
  name : String
  /// 1-based library ordinal, or 0 for the main image.
  library_ordinal : UInt32
  /// `DYLD_CHAINED_IMPORT` has no weak bit, but the 8-byte form does; kept
  /// uniform so both formats produce the same struct.
  weak : Bool
}

///|
/// Where one segment's chain table starts.
pub(all) struct SegmentChains {
  /// The segment's index in the image's segment list.
  segment_index : Int64
  /// `page_size`: log2 of the page size the entries cover, 0 when the segment
  /// is a single run.
  page_size : UInt32
  /// `pointer_format`: which pointer layout the chain uses.
  pointer_format : UInt32
  /// Byte offset of each page's first fixup, relative to the segment's vmaddr.
  page_starts : Array[UInt32]
}

///|
/// The decoded fixup index.
pub(all) struct ChainedFixups {
  /// `version` of the blob.
  version : UInt32
  /// The imports, in table order; a slot's 24-bit field indexes this list.
  imports : Array[ChainedImport]
  /// Per-segment chain tables. Entries for segments with no fixups are omitted.
  segments : Array[SegmentChains]
}

///|
/// One resolved fixup: a slot in a mapped section that holds a pointer.
pub(all) struct Fixup {
  /// Address of the slot itself.
  address : Int64
  /// For a rebase, the address the slot points at. For a bind, the named
  /// import's own target is not in this file, so this is meaningless.
  target : Int64
  /// Index into `ChainedFixups.imports`, or `None` for a rebase.
  import_index : Int64?
  /// The symbol this slot binds to, when it is a bind.
  symbol : String?
  /// The library ordinal for a bind.
  library_ordinal : UInt32
}

///|
/// Whether the fixup is a bind rather than a rebase.
pub fn Fixup::is_bind(self : Fixup) -> Bool {
  self.import_index is Some(_)
}

///|
/// Reads the chained-fixups blob referenced by `LC_DYLD_CHAINED_FIXUPS`.
pub fn chained_fixups(slice : MachSlice) -> ChainedFixups? raise MachscopeError {
  let mut region_off = -1L
  let mut region_size = 0L
  for cmd in slice.commands {
    if cmd.cmd != LC_DYLD_CHAINED_FIXUPS {
      continue
    }
    let body = command_payload(slice, cmd)
    let cur = Cursor::{ pos: body.start, endian: slice.header.kind.endian(), }
    let (off, cur) = body.read_u32(cur)
    let (size, _) = body.read_u32(cur)
    region_off = slice.bounds.start + off.to_int64()
    region_size = size.to_int64()
  }
  if region_off < 0L {
    return None
  }
  slice.bounds.require(region_off, region_size, "chained fixups")
  let b = slice.bounds
  let e = Endian::Little
  let c = Cursor::{ pos: region_off, endian: e, }
  let (version, c) = b.read_u32(c)
  let (starts_off, c) = b.read_u32(c)
  let (imports_off, c) = b.read_u32(c)
  let (symbols_off, c) = b.read_u32(c)
  let (imports_count, c) = b.read_u32(c)
  let (imports_format, c) = b.read_u32(c)
  let (symbols_format, _) = b.read_u32(c)
  if symbols_format != 0U {
    // 0 means the symbol pool is plain NUL-separated strings; a compressed pool
    // uses a different encoding this version does not decode.
    raise Unsupported(what="compressed symbol pool")
  }
  if imports_format != CHAINED_IMPORT_FORMAT && imports_format != 3U {
    raise Unsupported(what="chained import format")
  }
  let symbols_at = region_off + symbols_off.to_int64()
  let imports = read_imports(
    b,
    region_off + imports_off.to_int64(),
    imports_count,
    imports_format,
    symbols_at,
    region_off + region_size,
  )
  let segments = read_segment_chains(
    slice,
    region_off + starts_off.to_int64(),
    region_off + region_size,
  )
  Some(ChainedFixups::{ version, imports, segments, })
}

///|
/// Reads the import table.
///
/// The 4-byte format packs a 4-bit library ordinal above a 24-bit symbol
/// offset; the 8-byte format widens both and adds a weak bit.
fn read_imports(
  b : Bounds,
  at : Int64,
  count : UInt32,
  format : UInt32,
  symbols_at : Int64,
  limit : Int64,
) -> Array[ChainedImport] raise MachscopeError {
  let e = Endian::Little
  let entry = if format == CHAINED_IMPORT_FORMAT { 4L } else { 8L }
  b.require(at, entry * count.to_int64(), "chained imports")
  let out : Array[ChainedImport] = []
  let mut pos = at
  for _ in 0..<count.reinterpret_as_int() {
    let c = Cursor::{ pos, endian: e, }
    let (raw, c) = b.read_u32(c)
    let raw64 = raw.to_int64()
    // DYLD_CHAINED_IMPORT packs three fields into one word: the library
    // ordinal in the low 8 bits, a single reserved bit, and the symbol's offset
    // into the pool in the remaining 23. Reading the offset from bit 8 rather
    // than bit 9 doubles every name offset and lands one character into the
    // neighbouring string.
    let ordinal = if format == CHAINED_IMPORT_FORMAT {
      let raw_ordinal = raw64 & 0xFFL
      // Values above 0xF0 are two's-complement negative ordinals naming
      // libraries the linker synthesised.
      if raw_ordinal > 0xF0L {
        raise Unsupported(what="negative library ordinal in chained import")
      }
      raw_ordinal.to_int().reinterpret_as_uint()
    } else {
      raw64.to_int().reinterpret_as_uint()
    }
    let name_off = if format == CHAINED_IMPORT_FORMAT {
      (raw64 >> 9) & 0x007F_FFFFL
    } else {
      (raw64 >> 32) & 0xFFFF_FFFFL
    }
    let mut c2 = c
    let mut weak = false
    if format != CHAINED_IMPORT_FORMAT {
      let (flags, c3) = b.read_u32(c2)
      weak = (flags.to_int64() & 0x1L) != 0L
      c2 = c3
    }
    let name = read_pool_string(b, symbols_at + name_off, limit)
    out.push(ChainedImport::{
      name_offset: name_off.to_int().reinterpret_as_uint(),
      name,
      library_ordinal: ordinal,
      weak,
    })
    pos = c2.pos
  }
  out
}

///|
/// Reads a NUL-terminated string from the symbol pool.
fn read_pool_string(
  b : Bounds,
  at : Int64,
  limit : Int64,
) -> String raise MachscopeError {
  if at < 0L || at >= limit {
    raise OutOfBounds(what="chained symbol", offset=at, size=1L, limit~)
  }
  let buf = StringBuilder()
  let mut pos = at
  let mut done = false
  while !done {
    b.require(pos, 1L, "chained symbol")
    let byte = b.bytes.at(pos.to_int())
    pos = pos + 1L
    if byte.to_int() == 0 {
      done = true
    } else {
      buf.write_char(byte.to_char())
    }
  }
  buf.to_string()
}

///|
/// Reads the per-segment chain tables.
///
/// The starts table is an array of offsets, one per segment, and an offset of
/// zero means that segment has no fixups. Each non-zero offset points at a
/// `dyld_chained_starts_in_segment` whose own page list follows it.
fn read_segment_chains(
  slice : MachSlice,
  at : Int64,
  limit : Int64,
) -> Array[SegmentChains] raise MachscopeError {
  let b = slice.bounds
  let e = Endian::Little
  let (seg_count, c) = b.read_u32(Cursor::{ pos: at, endian: e, })
  b.require(c.pos, seg_count.to_int64() * 4L, "chained starts table")
  let out : Array[SegmentChains] = []
  let mut pos = c.pos
  for i in 0..<seg_count.reinterpret_as_int() {
    let (seg_off, c2) = b.read_u32(Cursor::{ pos, endian: e, })
    pos = c2.pos
    if seg_off == 0U {
      continue
    }
    let info = at + seg_off.to_int64()
    let ic = Cursor::{ pos: info, endian: e, }
    // dyld_chained_starts_in_segment: size (u32), page_size (u16),
    // pointer_format (u16), segment_offset (u64), max_valid_pointer (u32),
    // page_count (u16), then page_start[]. The list starts at offset 22, not
    // 24: there is no padding word after page_count, and reading from 24 lands
    // one entry into the list.
    let (_, ic) = b.read_u32(ic) // size
    let (page_size, ic) = b.read_u16(ic)
    let (pointer_format, ic) = b.read_u16(ic)
    let (_, ic) = b.read_u64(ic) // segment_offset
    let (_, ic) = b.read_u32(ic) // max_valid_pointer
    let (page_count, ic) = b.read_u16(ic)
    b.require(ic.pos, page_count.to_int64() * 2L, "chained page starts")
    let starts : Array[UInt32] = []
    let mut pc = ic.pos
    for _ in 0..<page_count.reinterpret_as_int() {
      let (s, c3) = b.read_u16(Cursor::{ pos: pc, endian: e, })
      starts.push(s)
      pc = c3.pos
    }
    let _ = limit
    out.push(SegmentChains::{
      segment_index: i.to_int64(),
      page_size: page_size.reinterpret_as_int().reinterpret_as_uint(),
      pointer_format: pointer_format.reinterpret_as_int().reinterpret_as_uint(),
      page_starts: starts,
    })
  }
  out
}

///|
/// Walks every chain and returns the resolved fixups.
///
/// A slot's low bits say whether it is a bind or a rebase and where the next
/// slot in its chain is. The walk therefore needs the segment's mapped address
/// as well as its file contents: the chain links by address, and an address
/// before the segment's start ends the chain.
pub fn fixups(slice : MachSlice) -> Array[Fixup] raise MachscopeError {
  let index = match chained_fixups(slice) {
    Some(c) => c
    None => return []
  }
  let segs = segments(slice)
  let out : Array[Fixup] = []
  let b = slice.bounds
  let e = slice.header.kind.endian()
  for chains in index.segments {
    if chains.segment_index >= segs.length().to_int64() {
      continue
    }
    // The arm64e formats carry a key, a diversity value and an address
    // discriminator in the bits the plain 64-bit format uses for the import
    // ordinal. Decoding them needs the format-specific tables this version does
    // not implement, so a chain in one of those segments is reported rather
    // than walked into a wrong answer.
    if chains.pointer_format == CHAINED_PTR_ARM64E {
      raise Unsupported(what="arm64e authenticated fixup chains")
    }
    if chains.pointer_format == CHAINED_PTR_ARM64E_USERLAND {
      raise Unsupported(what="arm64e userland fixup chains")
    }
    let seg = segs[chains.segment_index.to_int()]
    // `page_size` is a byte count, not a log2 shift: the linker writes 0x4000
    // for a 16 KiB page. A zero means the segment is one run rather than pages.
    let page_bytes = if chains.page_size == 0U {
      seg.vmsize
    } else {
      chains.page_size.reinterpret_as_int().to_int64()
    }
    for page in 0..<chains.page_starts.length() {
      let start = chains.page_starts[page]
      if start == 0xFFFFU {
        // 0xFFFF marks a page with no fixups, as opposed to a chain that
        // begins at offset 0.
        continue
      }
      let page_base = seg.vmaddr + page.to_int64() * page_bytes
      let mut slot_addr = page_base + start.to_int64() * 4L
      let mut steps = 0
      let mut walking = true
      while walking {
        steps = steps + 1
        if steps > 100_000 {
          raise LimitExceeded(what="fixup chain length", limit=100_000L)
        }
        let offset = match file_offset_of_address(segs, slot_addr) {
          Some(o) => o
          // A slot outside the segment's file bytes ends the chain: the rest of
          // the segment is zero-fill and holds no pointers.
          None => {
            walking = false
            continue
          }
        }
        let c = Cursor::{ pos: offset, endian: e, }
        let (raw, _) = b.read_u64(c)
        let bind = (raw & 0x8000_0000_0000_0000L) != 0L
        // The next slot's distance is in the low 12 bits, in 4-byte units.
        let next = (raw & 0xFFFL) * 4L
        if bind {
          // Arm64e packs an authentication bit at the top and a 16-bit import
          // ordinal at bit 32; the plain 64-bit format uses the same bit range
          // for the ordinal. Reading from bit 48 in either case picks up the
          // auth flag and reports an import index that does not exist.
          let ordinal = (raw >> 32) & 0xFFL
          let import_index = (raw >> 32) & 0xFFFFL
          let (symbol, lib) = match lookup_import(index.imports, import_index) {
            Some(imp) => (Some(imp.name), imp.library_ordinal)
            None => (None, ordinal.to_int().reinterpret_as_uint())
          }
          out.push(Fixup::{
            address: slot_addr,
            target: 0L,
            import_index: Some(import_index),
            symbol,
            library_ordinal: lib,
          })
        } else {
          // A rebase: the target is the low 36 bits, either an address or an
          // offset from the image base depending on the pointer format.
          let target = raw & 0x0000_000F_FFFF_FFFFL
          out.push(Fixup::{
            address: slot_addr,
            target,
            import_index: None,
            symbol: None,
            library_ordinal: 0U,
          })
        }
        if next == 0L {
          walking = false
        } else {
          slot_addr = slot_addr + next
        }
      }
    }
  }
  out
}

///|
/// Resolves an import index against the import table.
fn lookup_import(
  imports : Array[ChainedImport],
  index : Int64,
) -> ChainedImport? {
  if index < 0L || index >= imports.length().to_int64() {
    return None
  }
  Some(imports[index.to_int()])
}
