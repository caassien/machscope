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
/// `DYLD_CHAINED_PTR_ARM64E_USERLAND24`: identical to `_USERLAND` except the
/// bind ordinal is 24 bits wide rather than 16.
///
/// This is the format current linkers emit for userland arm64e binaries, so
/// leaving it out means every modern arm64e application fails with
/// `Unsupported` at its first fixup. The value is 12.
pub const CHAINED_PTR_ARM64E_USERLAND24 : UInt32 = 12

///|
/// `DYLD_CHAINED_PTR_ARM64E_FIRMWARE`: a firmware-only layout whose stride is
/// 4 bytes rather than 8 and whose unauthenticated target is a vmaddr.
pub const CHAINED_PTR_ARM64E_FIRMWARE : UInt32 = 10

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
  /// For an arm64e authenticated pointer: which key signs the target.
  key : UInt32
  /// For an arm64e authenticated pointer: the diversity value mixed into the
  /// signature. Two slots with the same target but different diversity cannot
  /// be swapped.
  diversity : UInt32
  /// Whether the slot also carries an address discriminator bit.
  has_discriminator : Bool
  /// Set for a lazy bind: a slot in `__la_symbol_ptr` that dyld leaves alone at
  /// load time and resolves on first call instead. It is still a bind, but a
  /// tool asking "what does the loader do at launch" wants it excluded, so the
  /// distinction is kept rather than flattened into `is_bind`.
  is_lazy : Bool
}

///|
/// Whether the fixup is a bind rather than a rebase.
///
/// A chained bind names its import by index; a classic bind names it by symbol
/// string and has no index at all, so the symbol is what decides there. Testing
/// only `import_index` classified every classic bind as a rebase.
pub fn Fixup::is_bind(self : Fixup) -> Bool {
  self.import_index is Some(_) || self.symbol is Some(_)
}

///|
/// A decoded chain slot, before it is given its address.
priv enum SlotKind {
  /// Points at an import: `(index, key, diversity, has_discriminator)`.
  Bind(Int64, UInt32, UInt32, Bool)
  /// Points inside the image: `(target, key, diversity, has_discriminator)`.
  Rebase(Int64, UInt32, UInt32, Bool)
}

///|
/// Decodes one slot according to its segment's pointer format.
///
/// The formats differ in where the bind flag lives, how wide the target is and
/// whether an authentication signature is attached. A format this function does
/// not know returns `None`, which the walk turns into an `Unsupported` error:
/// guessing at a layout produces plausible-looking wrong addresses.
fn decode_slot(raw : Int64, format : UInt32) -> SlotKind? {
  match format {
    // dyld_chained_ptr_64_bind / dyld_chained_ptr_64_rebase. The bind flag is
    // the sign bit and the next stride is in the low 12 bits.
    CHAINED_PTR_64 | CHAINED_PTR_64_OFFSET => {
      let bind = (raw & 0x8000_0000_0000_0000L) != 0L
      if bind {
        // ordinal:24 at bit 0, reserved:8, next:12, bind:1.
        Some(SlotKind::Bind(raw & 0x00FF_FFFFL, 0U, 0U, false))
      } else {
        // target:36 at bit 0, high8:8, reserved:7, next:12, bind:1.
        Some(SlotKind::Rebase(raw & 0x0000_000F_FFFF_FFFFL, 0U, 0U, false))
      }
    }
    // dyld_chained_ptr_arm64e_bind / _auth_bind / _rebase / _auth_rebase.
    //
    //   bit 63 auth, bit 62 bind, bits 51..61 next,
    //   auth form: ordinal:16 at bit 0, zero:16, diversity:16,
    //              addrDiv:1 at bit 48, key:2 at bit 49
    //   plain form: ordinal:16 at bit 0, zero:16, high8:8 at bit 32
    //
    // The `_USERLAND24` format keeps this layout and only widens the bind
    // ordinal to 24 bits, so it is handled here with the width as a parameter
    // rather than as a second copy of the branch.
    CHAINED_PTR_ARM64E
    | CHAINED_PTR_ARM64E_USERLAND
    | CHAINED_PTR_ARM64E_USERLAND24 => {
      let ordinal_mask = if format == CHAINED_PTR_ARM64E_USERLAND24 {
        0xFF_FFFFL
      } else {
        0xFFFFL
      }
      let auth = (raw & 0x8000_0000_0000_0000L) != 0L
      let bind = (raw & 0x4000_0000_0000_0000L) != 0L
      if bind {
        if auth {
          let import_index = raw & ordinal_mask
          let diversity = (raw >> 32) & 0xFFFFL
          let discriminator = (raw >> 48) & 0x1L
          let key = (raw >> 49) & 0x3L
          Some(
            SlotKind::Bind(
              import_index,
              key.to_int().reinterpret_as_uint(),
              diversity.to_int().reinterpret_as_uint(),
              discriminator != 0L,
            ),
          )
        } else {
          Some(SlotKind::Bind(raw & ordinal_mask, 0U, 0U, false))
        }
      } else if auth {
        // auth_rebase: target:32 at bit 0, diversity:16 at bit 32,
        //              addrDiv:1 at bit 48, key:2 at bit 49.
        let target = raw & 0xFFFF_FFFFL
        let diversity = (raw >> 32) & 0xFFFFL
        let discriminator = (raw >> 48) & 0x1L
        let key = (raw >> 49) & 0x3L
        Some(
          SlotKind::Rebase(
            target,
            key.to_int().reinterpret_as_uint(),
            diversity.to_int().reinterpret_as_uint(),
            discriminator != 0L,
          ),
        )
      } else {
        // rebase: target:43 at bit 0, high8:8 at bit 43.
        Some(SlotKind::Rebase(raw & 0x0000_07FF_FFFF_FFFFL, 0U, 0U, false))
      }
    }
    _ => None
  }
}

///|
/// The distance in bytes from this slot to the next in its chain.
///
/// `next` sits at bit 51 in every format; the formats differ only in the width
/// of the field and the unit its value counts in. Arm64e has 11 bits counting
/// 8-byte pointers; the plain 64-bit formats have 12 bits counting 4-byte words.
///
/// Getting either wrong ends the walk early rather than misreporting a single
/// slot, which is what makes this worth spelling out: an earlier version read
/// the plain 64-bit stride from the low 12 bits, which are the low bits of
/// `target` or `ordinal`. Those are near-always nonzero, so the walk advanced
/// into the middle of the pointer array and stopped when it hit something that
/// decoded as `next == 0`. On `/usr/bin/ssh` that found 12 fixups where
/// `dyld_info` reports 1024.
fn slot_stride(raw : Int64, format : UInt32) -> Int64 {
  match format {
    CHAINED_PTR_ARM64E
    | CHAINED_PTR_ARM64E_USERLAND
    | CHAINED_PTR_ARM64E_USERLAND24 => ((raw >> 51) & 0x7FFL) * 8L
    _ => ((raw >> 51) & 0xFFFL) * 4L
  }
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
  // 1 = DYLD_CHAINED_IMPORT, 2 = _ADDEND, 3 = _ADDEND64. All three appear in
  // shipping binaries: the arm64 slice of `/usr/bin/afclip` uses 2 while the
  // x86_64 slice uses 1, and `afconvert` uses 3.
  if imports_format < 1U || imports_format > 3U {
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
/// `DYLD_CHAINED_IMPORT` is one word: an 8-bit library ordinal, a reserved bit
/// and a 23-bit symbol offset. `DYLD_CHAINED_IMPORT_ADDEND` and
/// `_ADDEND64` are two words: the same fields widened to 16 and 32 bits, then a
/// 32-bit flags word and a 64-bit addend. The entry sizes differ, which is why
/// the loop reads a fixed shape per format rather than a variable one.
fn read_imports(
  b : Bounds,
  at : Int64,
  count : UInt32,
  format : UInt32,
  symbols_at : Int64,
  limit : Int64,
) -> Array[ChainedImport] raise MachscopeError {
  let e = Endian::Little
  // 4 bytes packed, 8 with a separate flags word, 16 when a 64-bit addend
  // follows the flags.
  let entry = if format == CHAINED_IMPORT_FORMAT {
    4L
  } else if format == 3U {
    16L
  } else {
    8L
  }
  b.require(at, entry * count.to_int64(), "chained imports")
  let out : Array[ChainedImport] = []
  let mut pos = at
  for _ in 0..<count.reinterpret_as_int() {
    let c = Cursor::{ pos, endian: e, }
    let (raw, c) = b.read_u32(c)
    let raw64 = raw.to_int64()
    let _ = c
    // DYLD_CHAINED_IMPORT packs three fields into one word: the library
    // ordinal in the low 8 bits, a single reserved bit, and the symbol's offset
    // into the pool in the remaining 23. Reading the offset from bit 8 rather
    // than bit 9 doubles every name offset and lands one character into the
    // neighbouring string.
    let ordinal = if format == CHAINED_IMPORT_FORMAT {
      // lib_ordinal is `int8` in `dyld_chained_import`, so 0x80..0xFF are the
      // negative special ordinals (SELF, MAIN_EXECUTABLE, FLAT_LOOKUP,
      // WEAK_LOOKUP). They are valid and mean "not a dylib"; reporting them as
      // an error rejected every binary that uses one, which is most of the
      // system's tools. Widening to `UInt32` keeps them distinguishable, which
      // is what the library-ordinal field is for.
      (raw64 & 0xFFL).to_int().reinterpret_as_uint()
    } else {
      raw64.to_int().reinterpret_as_uint()
    }
    // `dyld_chained_import_addend` reuses the first word's field positions, so the
    // name offset moves from bit 9 to bit 16 only in the 64-bit variant;
    // `_ADDEND` (format 2) keeps bit 9. Getting this wrong reads the name from the
    // middle of the preceding one, which is how "unsupported" turned into
    // "garbage" the first time this branch was written.
    let name_off = if format == CHAINED_IMPORT_FORMAT || format == 2U {
      (raw64 >> 9) & 0x007F_FFFFL
    } else {
      (raw64 >> 16) & 0xFFFF_FFFFL
    }
    let mut c2 = c
    let mut weak = false
    if format != CHAINED_IMPORT_FORMAT {
      let (flags, c3) = b.read_u32(c2)
      weak = (flags.to_int64() & 0x1L) != 0L
      c2 = c3
      if format == 3U {
        // `_ADDEND64` carries a 64-bit addend after the flags.
        let (_, c4) = b.read_u64(c2)
        c2 = c4
      }
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
    // No chained fixups. Older images describe the same relocations with the
    // `LC_DYLD_INFO` opcode streams instead, and x86_64 slices of universal
    // binaries still do; returning an empty array there would report "this
    // image has no fixups", which is a different and wrong answer.
    None => return classic_fixups(slice)
  }
  let segs = segments(slice)
  // The address an offset-form rebase counts from: the lowest mapped address,
  // which is where dyld loads the image. `__PAGEZERO` maps from zero and has no
  // file bytes, so it is skipped; every other segment follows it.
  let mut image_base = 0L
  let mut base_set = false
  for seg in segs {
    if seg.file_size == 0L && seg.name == "__PAGEZERO" {
      continue
    }
    if !base_set || seg.vmaddr < image_base {
      image_base = seg.vmaddr
      base_set = true
    }
  }
  let mut image_end = image_base
  for seg in segs {
    if seg.vmaddr + seg.vmsize > image_end {
      image_end = seg.vmaddr + seg.vmsize
    }
  }
  let out : Array[Fixup] = []
  let b = slice.bounds
  let e = slice.header.kind.endian()
  for chains in index.segments {
    if chains.segment_index >= segs.length().to_int64() {
      continue
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
      // The page start is a byte offset into the page. The unit documented for
      // older dyld versions is a 4-byte word, but the value written by the
      // current linker is already in bytes: a page whose first fixup sits 8
      // bytes in carries 8, not 2.
      let mut slot_addr = page_base + start.to_int64()
      let mut steps = 0
      let mut walking = true
      while walking {
        steps = steps + 1
        if steps > 100_000 {
          raise LimitExceeded(what="fixup chain length", limit=100_000L)
        }
        // `file_offset_of_address` answers in image-relative terms, which is
        // what the load commands record. Inside a fat slice that is not where
        // the bytes sit in the file this cursor reads, so the slice's own start
        // goes back on.
        let offset = match file_offset_of_address(segs, slot_addr) {
          Some(o) => b.start + o
          // A slot outside the segment's file bytes ends the chain: the rest of
          // the segment is zero-fill and holds no pointers.
          None => {
            walking = false
            continue
          }
        }
        let c = Cursor::{ pos: offset, endian: e, }
        let (raw, _) = b.read_u64(c)
        let decoded = decode_slot(raw, chains.pointer_format)
        match decoded {
          Some(slot) =>
            match slot {
              SlotKind::Bind(import_index, key, diversity, has_discriminator) => {
                let (symbol, lib) = match
                  lookup_import(index.imports, import_index) {
                  Some(imp) => (Some(imp.name), imp.library_ordinal)
                  None => (None, import_index.to_int().reinterpret_as_uint())
                }
                out.push(Fixup::{
                  address: slot_addr,
                  target: 0L,
                  import_index: Some(import_index),
                  symbol,
                  library_ordinal: lib,
                  key,
                  diversity,
                  has_discriminator,
                  is_lazy: false,
                })
              }
              SlotKind::Rebase(target, key, diversity, has_discriminator) =>
                out.push(Fixup::{
                  address: slot_addr,
                  // A plain 64-bit rebase stores a *virtual address* in its 36
                  // target bits. An arm64e one stores a 32- or 43-bit offset
                  // from the image base instead. `dyld_info` prints both as
                  // final addresses, so the offset form is rebased here; doing
                  // it in `decode_slot` would make that function depend on the
                  // segment table, which is not where bit layout belongs.
                  target: resolve_rebase_target(
                    target,
                    chains.pointer_format,
                    image_base,
                    image_end,
                  ),
                  import_index: None,
                  symbol: None,
                  library_ordinal: 0U,
                  key,
                  diversity,
                  has_discriminator,
                  is_lazy: false,
                })
            }
          None => raise Unsupported(what="chained pointer format")
        }
        // The next slot's distance is in the low bits; the unit differs by
        // format, and arm64e counts in 8-byte slots where the 64-bit formats
        // count in 4-byte words.
        let next = slot_stride(raw, chains.pointer_format)
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

// Classic dyld info.
//
// Before chained fixups, an image described its own relocations with two opcode
// streams named by `LC_DYLD_INFO` / `LC_DYLD_INFO_ONLY`: one for rebases, one
// for binds. Each stream is a small bytecode over a cursor that walks the
// image's address space; the opcodes say where to set the cursor, mask it, and
// then emit a fixup at it.
//
// This is a different encoding of the same information, not a different
// question, so it decodes into the same `Fixup`. The reason it has to be
// decoded at all is that x86_64 slices of universal binaries still use it:
// `ls`, `cp`, `mv` and 68 others in `/usr/bin` carry no `LC_DYLD_CHAINED_FIXUPS`,
// and a parser that only knows the chained form reports them as having no
// fixups rather than as being unreadable.

///|
/// `REBASE_OPCODE_MASK`: the opcode is the high nibble of the byte.
const REBASE_OPCODE_MASK : UInt32 = 0xF0

///|
/// `REBASE_IMMEDIATE_MASK`: the low nibble is an immediate operand, or the
/// count for the `*_IMM` forms.
const REBASE_IMMEDIATE_MASK : UInt32 = 0x0F

///|
/// `REBASE_OPCODE_DONE`: the end of the stream.
const REBASE_OPCODE_DONE : UInt32 = 0x00

///|
/// `REBASE_OPCODE_SET_TYPE_IMM`.
const REBASE_OPCODE_SET_TYPE_IMM : UInt32 = 0x10

///|
/// `REBASE_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB`.
const REBASE_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB : UInt32 = 0x20

///|
/// `REBASE_OPCODE_ADD_ADDR_ULEB`.
const REBASE_OPCODE_ADD_ADDR_ULEB : UInt32 = 0x30

///|
/// `REBASE_OPCODE_ADD_ADDR_IMM_SCALED`.
const REBASE_OPCODE_ADD_ADDR_IMM_SCALED : UInt32 = 0x40

///|
/// `REBASE_OPCODE_DO_REBASE_IMM_TIMES`.
const REBASE_OPCODE_DO_REBASE_IMM_TIMES : UInt32 = 0x50

///|
/// `REBASE_OPCODE_DO_REBASE_ULEB_TIMES`.
const REBASE_OPCODE_DO_REBASE_ULEB_TIMES : UInt32 = 0x60

///|
/// `REBASE_OPCODE_DO_REBASE_ADD_ADDR_ULEB`.
const REBASE_OPCODE_DO_REBASE_ADD_ADDR_ULEB : UInt32 = 0x70

///|
/// `REBASE_OPCODE_DO_REBASE_ULEB_TIMES_SKIPPING_ULEB`.
const REBASE_OPCODE_DO_REBASE_ULEB_TIMES_SKIPPING_ULEB : UInt32 = 0x80

///|
/// `BIND_OPCODE_MASK`.
const BIND_OPCODE_MASK : UInt32 = 0xF0

///|
/// `BIND_IMMEDIATE_MASK`.
const BIND_IMMEDIATE_MASK : UInt32 = 0x0F

///|
/// `BIND_OPCODE_DONE`.
const BIND_OPCODE_DONE : UInt32 = 0x00

///|
/// `BIND_OPCODE_SET_DYLIB_ORDINAL_IMM`.
const BIND_OPCODE_SET_DYLIB_ORDINAL_IMM : UInt32 = 0x10

///|
/// `BIND_OPCODE_SET_DYLIB_ORDINAL_ULEB`.
const BIND_OPCODE_SET_DYLIB_ORDINAL_ULEB : UInt32 = 0x20

///|
/// `BIND_OPCODE_SET_DYLIB_SPECIAL_IMM`.
const BIND_OPCODE_SET_DYLIB_SPECIAL_IMM : UInt32 = 0x30

///|
/// `BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM`.
const BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM : UInt32 = 0x40

///|
/// `BIND_OPCODE_SET_TYPE_IMM`.
const BIND_OPCODE_SET_TYPE_IMM : UInt32 = 0x50

///|
/// `BIND_OPCODE_SET_ADDEND_SLEB`.
const BIND_OPCODE_SET_ADDEND_SLEB : UInt32 = 0x60

///|
/// `BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB`.
const BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB : UInt32 = 0x70

///|
/// `BIND_OPCODE_ADD_ADDR_ULEB`.
const BIND_OPCODE_ADD_ADDR_ULEB : UInt32 = 0x80

///|
/// `BIND_OPCODE_DO_BIND`.
const BIND_OPCODE_DO_BIND : UInt32 = 0x90

///|
/// `BIND_OPCODE_DO_BIND_ADD_ADDR_ULEB`.
const BIND_OPCODE_DO_BIND_ADD_ADDR_ULEB : UInt32 = 0xA0

///|
/// `BIND_OPCODE_DO_BIND_ADD_ADDR_IMM_SCALED`.
const BIND_OPCODE_DO_BIND_ADD_ADDR_IMM_SCALED : UInt32 = 0xB0

///|
/// `BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIPPING_ULEB`.
const BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIPPING_ULEB : UInt32 = 0xC0

///|
/// The four `rebase_*`/`bind_*` region pairs of a classic `LC_DYLD_INFO`.
pub(all) struct DyldInfo {
  /// `rebase_off`: file offset of the rebase opcode stream.
  rebase_off : Int64
  /// `rebase_size`: byte length of the rebase stream.
  rebase_size : Int64
  /// `bind_off`: file offset of the non-lazy bind stream.
  bind_off : Int64
  /// `bind_size`: byte length of the bind stream.
  bind_size : Int64
  /// `weak_bind_off`: file offset of the weak bind stream.
  weak_bind_off : Int64
  /// `weak_bind_size`: byte length of the weak bind stream.
  weak_bind_size : Int64
  /// `lazy_bind_off`: file offset of the lazy bind stream.
  lazy_bind_off : Int64
  /// `lazy_bind_size`: byte length of the lazy bind stream.
  lazy_bind_size : Int64
}

///|
/// Reads the `LC_DYLD_INFO` / `LC_DYLD_INFO_ONLY` command, if there is one.
pub fn dyld_info(slice : MachSlice) -> DyldInfo? raise MachscopeError {
  for cmd in slice.commands {
    if cmd.cmd != LC_DYLD_INFO && cmd.cmd != LC_DYLD_INFO_ONLY {
      continue
    }
    let body = command_payload(slice, cmd)
    let e = slice.header.kind.endian()
    let mut c = Cursor::{ pos: body.start, endian: e, }
    let (rebase_off, c1) = body.read_u32(c)
    let (rebase_size, c2) = body.read_u32(c1)
    let (bind_off, c3) = body.read_u32(c2)
    let (bind_size, c4) = body.read_u32(c3)
    let (weak_bind_off, c5) = body.read_u32(c4)
    let (weak_bind_size, c6) = body.read_u32(c5)
    let (lazy_bind_off, c7) = body.read_u32(c6)
    let (lazy_bind_size, c8) = body.read_u32(c7)
    c = c8
    let _ = c
    let base = slice.bounds.start
    return Some(DyldInfo::{
      rebase_off: base + rebase_off.to_int64(),
      rebase_size: rebase_size.to_int64(),
      bind_off: base + bind_off.to_int64(),
      bind_size: bind_size.to_int64(),
      weak_bind_off: base + weak_bind_off.to_int64(),
      weak_bind_size: weak_bind_size.to_int64(),
      lazy_bind_off: base + lazy_bind_off.to_int64(),
      lazy_bind_size: lazy_bind_size.to_int64(),
    })
  }
  None
}

///|
/// Whether this slice describes its relocations with the classic
/// `LC_DYLD_INFO` opcode streams rather than chained fixups.
///
/// The distinction matters to a caller because `fixups` returns an empty array
/// for a slice that has neither, and "this image has no fixups" and "this image
/// uses an encoding the parser does not read" are different answers.
pub fn uses_classic_dyld_info(slice : MachSlice) -> Bool raise MachscopeError {
  match chained_fixups(slice) {
    Some(_) => false
    None => dyld_info(slice) is Some(_)
  }
}

///|
/// Turns a segment index and an in-segment offset into an offset inside the
/// whole file.
///
/// The opcode streams address memory, not files; a slot in a zero-fill part of
/// a segment has no bytes to read and no fixup to report. `base` is the slice's
/// own start, which is what turns the load command's image-relative
/// `file_offset` into a position in the buffer this parser reads from.
fn classic_file_offset(
  segs : Array[Segment],
  seg_index : Int64,
  seg_offset : Int64,
  base : Int64,
) -> Int64? {
  if seg_index < 0L || seg_index >= segs.length().to_int64() {
    return None
  }
  let seg = segs[seg_index.to_int()]
  if seg_offset < 0L || seg_offset >= seg.file_size {
    return None
  }
  Some(base + seg.file_offset + seg_offset)
}

///|
/// Walks a classic rebase opcode stream.
fn walk_rebases(
  b : Bounds,
  start : Int64,
  size : Int64,
  segs : Array[Segment],
  out : Array[Fixup],
) -> Unit raise MachscopeError {
  if size == 0L {
    return
  }
  b.require(start, size, "rebase opcodes")
  let e = b.read_u32(Cursor::{ pos: start, endian: Endian::Little, })
  let _ = e
  let mut cur = Cursor::{ pos: start, endian: Endian::Little, }
  let end = start + size
  let mut seg_index = 0L
  let mut seg_offset = 0L
  let mut steps = 0
  let mut done = false
  while !done && cur.pos < end {
    steps = steps + 1
    if steps > 1_000_000 {
      raise LimitExceeded(what="rebase opcode count", limit=1_000_000L)
    }
    let (byte, c1) = b.read_u8(cur)
    cur = c1
    let opcode = byte & REBASE_OPCODE_MASK
    let imm = (byte & REBASE_IMMEDIATE_MASK).to_int64()
    match opcode {
      REBASE_OPCODE_DONE => done = true
      REBASE_OPCODE_SET_TYPE_IMM => ()
      REBASE_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB => {
        seg_index = imm
        let (v, c2) = read_uleb128(b, cur)
        seg_offset = v.reinterpret_as_int64()
        cur = c2
      }
      REBASE_OPCODE_ADD_ADDR_ULEB => {
        let (v, c2) = read_uleb128(b, cur)
        seg_offset = seg_offset + v.reinterpret_as_int64()
        cur = c2
      }
      REBASE_OPCODE_ADD_ADDR_IMM_SCALED => seg_offset = seg_offset + imm * 8L
      REBASE_OPCODE_DO_REBASE_IMM_TIMES =>
        for _ in 0..<imm.to_int() {
          emit_rebase(b, segs, seg_index, seg_offset, out)
          seg_offset = seg_offset + 8L
        }
      REBASE_OPCODE_DO_REBASE_ULEB_TIMES => {
        let (v, c2) = read_uleb128(b, cur)
        cur = c2
        let n = v.reinterpret_as_int64()
        for _ in 0..<n.to_int() {
          emit_rebase(b, segs, seg_index, seg_offset, out)
          seg_offset = seg_offset + 8L
        }
      }
      REBASE_OPCODE_DO_REBASE_ADD_ADDR_ULEB => {
        emit_rebase(b, segs, seg_index, seg_offset, out)
        let (v, c2) = read_uleb128(b, cur)
        cur = c2
        seg_offset = seg_offset + 8L + v.reinterpret_as_int64()
      }
      REBASE_OPCODE_DO_REBASE_ULEB_TIMES_SKIPPING_ULEB => {
        let (v, c2) = read_uleb128(b, cur)
        let (skip, c3) = read_uleb128(b, c2)
        cur = c3
        let n = v.reinterpret_as_int64()
        let s = skip.reinterpret_as_int64()
        for _ in 0..<n.to_int() {
          emit_rebase(b, segs, seg_index, seg_offset, out)
          seg_offset = seg_offset + 8L + s
        }
      }
      _ => raise Unsupported(what="rebase opcode")
    }
  }
}

///|
/// Records one rebase at the current cursor position.
///
/// Unlike a chained rebase, whose target is packed into the slot's own bits,
/// a classic rebase leaves the slot holding the pointer it should end up with
/// once the image base is added. Reading the eight bytes back is what lets the
/// output name a target instead of reporting zero.
fn emit_rebase(
  b : Bounds,
  segs : Array[Segment],
  seg_index : Int64,
  seg_offset : Int64,
  out : Array[Fixup],
) -> Unit raise MachscopeError {
  if seg_index < 0L || seg_index >= segs.length().to_int64() {
    return
  }
  let seg = segs[seg_index.to_int()]
  let address = seg.vmaddr + seg_offset
  let target = match classic_file_offset(segs, seg_index, seg_offset, b.start) {
    Some(off) => {
      let (raw, _) = b.read_u64(Cursor::{ pos: off, endian: Endian::Little, })
      raw
    }
    // A slot in a zero-fill page has no bytes to read. dyld would still rebase
    // it at load time, so the fixup is reported with a zero target rather than
    // dropped.
    None => 0L
  }
  out.push(Fixup::{
    address,
    target,
    import_index: None,
    symbol: None,
    library_ordinal: 0U,
    key: 0U,
    diversity: 0U,
    has_discriminator: false,
    is_lazy: false,
  })
}

///|
/// Walks a classic bind opcode stream.
fn walk_binds(
  b : Bounds,
  start : Int64,
  size : Int64,
  segs : Array[Segment],
  lazy_~ : Bool,
  out : Array[Fixup],
) -> Unit raise MachscopeError {
  if size == 0L {
    return
  }
  b.require(start, size, "bind opcodes")
  let mut cur = Cursor::{ pos: start, endian: Endian::Little, }
  let end = start + size
  let mut seg_index = 0L
  let mut seg_offset = 0L
  let mut ordinal = 0U
  let mut name = ""
  let mut steps = 0
  let mut done = false
  while !done && cur.pos < end {
    steps = steps + 1
    if steps > 1_000_000 {
      raise LimitExceeded(what="bind opcode count", limit=1_000_000L)
    }
    let (byte, c1) = b.read_u8(cur)
    cur = c1
    let opcode = byte & BIND_OPCODE_MASK
    let imm = (byte & BIND_IMMEDIATE_MASK).to_int64()
    match opcode {
      BIND_OPCODE_DONE =>
        // In the lazy stream `DONE` separates one entry from the next rather
        // than ending the stream, so only stop when the stream is exhausted.
        //
        // Each entry there re-establishes its own symbol and ordinal, but a
        // stream that omits one would otherwise inherit the previous entry's,
        // and attribute a slot to a library that never mentions it. Clearing
        // both keeps an incomplete entry from borrowing its neighbour's name,
        // which is how `/usr/bin/stz` came to bind `__ZdlPv` in lib 0 — a
        // library the import table does not have.
        if cur.pos >= end {
          done = true
        } else {
          name = ""
          ordinal = 0U
        }
      BIND_OPCODE_SET_DYLIB_ORDINAL_IMM =>
        ordinal = imm.to_int().reinterpret_as_uint()
      BIND_OPCODE_SET_DYLIB_ORDINAL_ULEB => {
        let (v, c2) = read_uleb128(b, cur)
        cur = c2
        ordinal = v.reinterpret_as_int64().to_int().reinterpret_as_uint()
      }
      BIND_OPCODE_SET_DYLIB_SPECIAL_IMM =>
        // A zero immediate means ordinal 0; otherwise the value is sign
        // extended from the four bits, which is how the negative special
        // ordinals (`SELF`, `MAIN_EXECUTABLE`, `FLAT_LOOKUP`) are stored.
        ordinal = if imm == 0L {
          0U
        } else {
          let v = (imm | 0xF0L).to_int()
          v.reinterpret_as_uint()
        }
      BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM => {
        let (s, c2) = read_c_string(b, cur)
        name = s
        cur = c2
      }
      BIND_OPCODE_SET_TYPE_IMM => ()
      BIND_OPCODE_SET_ADDEND_SLEB => {
        let (_, c2) = read_sleb128(b, cur)
        cur = c2
      }
      BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB => {
        seg_index = imm
        let (v, c2) = read_uleb128(b, cur)
        seg_offset = v.reinterpret_as_int64()
        cur = c2
      }
      BIND_OPCODE_ADD_ADDR_ULEB => {
        let (v, c2) = read_uleb128(b, cur)
        seg_offset = seg_offset + v.reinterpret_as_int64()
        cur = c2
      }
      BIND_OPCODE_DO_BIND => {
        emit_bind(segs, seg_index, seg_offset, ordinal, name, lazy_, out)
        seg_offset = seg_offset + 8L
      }
      BIND_OPCODE_DO_BIND_ADD_ADDR_ULEB => {
        emit_bind(segs, seg_index, seg_offset, ordinal, name, lazy_, out)
        let (v, c2) = read_uleb128(b, cur)
        cur = c2
        seg_offset = seg_offset + 8L + v.reinterpret_as_int64()
      }
      BIND_OPCODE_DO_BIND_ADD_ADDR_IMM_SCALED => {
        emit_bind(segs, seg_index, seg_offset, ordinal, name, lazy_, out)
        seg_offset = seg_offset + 8L + imm * 8L
      }
      BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIPPING_ULEB => {
        let (v, c2) = read_uleb128(b, cur)
        let (skip, c3) = read_uleb128(b, c2)
        cur = c3
        let n = v.reinterpret_as_int64()
        let s = skip.reinterpret_as_int64()
        for _ in 0..<n.to_int() {
          emit_bind(segs, seg_index, seg_offset, ordinal, name, lazy_, out)
          seg_offset = seg_offset + 8L + s
        }
      }
      _ => raise Unsupported(what="bind opcode")
    }
  }
}

///|
/// Records one bind at the current cursor position.
fn emit_bind(
  segs : Array[Segment],
  seg_index : Int64,
  seg_offset : Int64,
  ordinal : UInt32,
  name : String,
  lazy_ : Bool,
  out : Array[Fixup],
) -> Unit {
  if seg_index < 0L || seg_index >= segs.length().to_int64() {
    return
  }
  let seg = segs[seg_index.to_int()]
  out.push(Fixup::{
    address: seg.vmaddr + seg_offset,
    target: 0L,
    import_index: None,
    symbol: Some(name),
    library_ordinal: ordinal,
    key: 0U,
    diversity: 0U,
    has_discriminator: false,
    is_lazy: lazy_,
  })
}

///|
/// Walks the classic dyld-info streams of a slice.
///
/// The three bind streams are concatenated in the order dyld applies them:
/// the non-lazy binds, the weak binds, then the lazy binds. `dyld_info` prints
/// them in file order, which is the same order, so the result lines up with it.
pub fn classic_fixups(slice : MachSlice) -> Array[Fixup] raise MachscopeError {
  let info = match dyld_info(slice) {
    Some(i) => i
    None => return []
  }
  let segs = segments(slice)
  let b = slice.bounds
  let out : Array[Fixup] = []
  walk_rebases(b, info.rebase_off, info.rebase_size, segs, out)
  walk_binds(b, info.bind_off, info.bind_size, segs, lazy_=false, out)
  walk_binds(b, info.weak_bind_off, info.weak_bind_size, segs, lazy_=false, out)
  // The lazy stream is the one dyld defers: these slots stay as they are until
  // the first call through them, which is why `dyld_info` labels them
  // `lazy-bind` rather than `bind`.
  walk_binds(b, info.lazy_bind_off, info.lazy_bind_size, segs, lazy_=true, out)
  out
}

///|
/// Decides whether a rebase's raw target is a virtual address or an offset
/// from the image base.
///
/// It cannot be decided from the pointer format alone, which is what an earlier
/// version of this code got wrong. Both forms occur in arm64e slots:
/// `/bin/chmod` stores `0x100002c2e` in a slot already, while `/bin/date` stores
/// `0x20be` for the same kind of pointer. The format says how the bits are laid
/// out, not whether the image base is among them.
///
/// So the test is where the value lands. A target that already falls inside
/// the image's mapped range is the address. One that does not, but does once the
/// base is added, is an offset. A value that is neither stays as it is: it
/// points somewhere outside this image, which is unusual but not unreadable.
fn resolve_rebase_target(
  raw : Int64,
  format : UInt32,
  image_base : Int64,
  image_end : Int64,
) -> Int64 {
  if raw >= image_base && raw < image_end {
    return raw
  }
  let biased = image_base + raw
  if biased >= image_base && biased < image_end {
    return biased
  }
  // `_64_OFFSET` is documented to be an offset and nothing else, so an image
  // whose segments do not cover the result still gets the base added.
  if format == CHAINED_PTR_64_OFFSET {
    return biased
  }
  raw
}
