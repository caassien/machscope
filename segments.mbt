// The segment and section table.
//
// A Mach-O file describes its own memory layout: `LC_SEGMENT_64` commands name
// the regions the loader maps, and each carries a table of sections describing
// the bytes within it. Reading them is what turns a byte offset into a virtual
// address and back, which is the prerequisite for symbolication later.

///|
/// One `section_64` entry.
pub(all) struct Section {
  /// `sectname`, e.g. `__text`.
  name : String
  /// `segname` repeated inside the section, e.g. `__TEXT`.
  segment_name : String
  /// `addr`: virtual address of the section's first byte.
  addr : Int64
  /// `size` in bytes.
  size : Int64
  /// `offset`: file offset of the section's first byte, or 0 for a zero-fill
  /// section.
  file_offset : UInt32
  /// `align`: log2 of the section's alignment.
  align : UInt32
  /// `reloff`: file offset of the relocation entries.
  reloc_offset : UInt32
  /// `nreloc`: number of relocation entries.
  nreloc : UInt32
  /// `flags`: the `S_*` attribute bits plus the section type.
  flags : UInt32
}

///|
/// The section type bits of `section.flags`.
pub const SECTION_TYPE : UInt32 = 0x0000_00FF

///|
/// `S_ZEROFILL`: the section occupies memory but no bytes in the file.
pub const S_ZEROFILL : UInt32 = 0x1

///|
/// `S_ATTR_DEBUG`: the section holds debugging information.
pub const S_ATTR_DEBUG : UInt32 = 0x0200_0000

///|
/// Whether this section occupies no file bytes.
pub fn Section::is_zero_fill(self : Section) -> Bool {
  (self.flags & SECTION_TYPE) == S_ZEROFILL
}

///|
/// Whether the section is marked as debug information.
///
/// This is the attribute `strip -S` looks at when deciding what to remove, and
/// the one that tells a reader a `__DWARF` section is worth parsing.
pub fn Section::is_debug(self : Section) -> Bool {
  (self.flags & S_ATTR_DEBUG) != 0U
}

///|
/// One `segment_command_64` with its sections.
pub(all) struct Segment {
  /// `segname`, e.g. `__TEXT`.
  name : String
  /// `vmaddr`: virtual address the segment is mapped at.
  vmaddr : Int64
  /// `vmsize`: bytes occupied in the address space.
  vmsize : Int64
  /// `fileoff`: offset of the segment's bytes in the file.
  file_offset : Int64
  /// `filesize`: bytes occupied in the file; may be less than `vmsize` when the
  /// segment ends in zero-fill memory.
  file_size : Int64
  /// `maxprot` and `initprot` as recorded.
  init_prot : UInt32
  /// `nsects`: number of section entries that follow the segment header.
  nsects : UInt32
  /// `flags`: the `SG_*` bits.
  flags : UInt32
  /// The sections this segment contains, in table order.
  sections : Array[Section]
}

///|
/// Whether a virtual address falls inside this segment.
pub fn Segment::contains_address(self : Segment, addr : Int64) -> Bool {
  addr >= self.vmaddr && addr < self.vmaddr + self.vmsize
}

///|
/// Whether a file offset falls inside the bytes this segment occupies on disk.
pub fn Segment::contains_offset(self : Segment, offset : Int64) -> Bool {
  offset >= self.file_offset && offset < self.file_offset + self.file_size
}

///|
/// Decodes every `LC_SEGMENT_64` in a slice.
///
/// 32-bit `LC_SEGMENT` is not decoded: every binary that carries DWARF today is
/// 64-bit, and silently returning an empty table for a 32-bit file would be
/// worse than the caller knowing. A 32-bit slice with segment commands is
/// reported as unsupported.
pub fn segments(slice : MachSlice) -> Array[Segment] raise MachscopeError {
  let out : Array[Segment] = []
  for cmd in slice.commands {
    if cmd.cmd == LC_SEGMENT {
      raise Unsupported(what="32-bit LC_SEGMENT decoding")
    }
    if cmd.cmd != LC_SEGMENT_64 {
      continue
    }
    out.push(segment_command(slice, cmd))
  }
  out
}

///|
/// Decodes one `LC_SEGMENT_64` and its section table.
///
/// The section count is taken from the command and the command's own `cmdsize`
/// must account for all of them; a command whose `cmdsize` is too small for its
/// `nsects` is rejected rather than read past.
fn segment_command(
  slice : MachSlice,
  cmd : RawCommand,
) -> Segment raise MachscopeError {
  let body = command_payload(slice, cmd)
  let endian = slice.header.kind.endian()
  // segment_command_64: segname[16], vmaddr, vmsize, fileoff, filesize,
  // maxprot, initprot, nsects, flags.
  let name = body.fixed_name(body.start, 16L, "segname")
  let cur = Cursor::{ pos: body.start + 16L, endian, }
  let (vmaddr, cur) = body.read_u64(cur)
  let (vmsize, cur) = body.read_u64(cur)
  let (file_offset, cur) = body.read_u64(cur)
  let (file_size, cur) = body.read_u64(cur)
  let (_, cur) = body.read_i32(cur) // maxprot
  let (init_prot, cur) = body.read_i32(cur)
  let (nsects, cur) = body.read_u32(cur)
  let (flags, _) = body.read_u32(cur)
  // The segment_command_64 payload is 72 bytes: segname[16] plus four 8-byte
  // addresses and sizes plus four 4-byte words. The 8-byte generic command
  // header precedes the payload, so the section table starts 72 bytes into the
  // command, which is 64 bytes past `body.start`.
  // Each section_64 is 80 bytes: sectname[16], segname[16], addr, size,
  // offset, align, reloff, nreloc, flags, reserved1..3.
  let section_base = body.start + 64L
  body.require(section_base, nsects.to_int64() * 80L, "section table")
  let sections : Array[Section] = []
  let mut at = section_base
  for _ in 0..<nsects.reinterpret_as_int() {
    let sect_name = body.fixed_name(at, 16L, "sectname")
    let seg_name = body.fixed_name(at + 16L, 16L, "section segname")
    let c = Cursor::{ pos: at + 32L, endian, }
    let (addr, c) = body.read_u64(c)
    let (size, c) = body.read_u64(c)
    let (file_off, c) = body.read_u32(c)
    let (align, c) = body.read_u32(c)
    let (reloff, c) = body.read_u32(c)
    let (nreloc, c) = body.read_u32(c)
    let (sflags, _) = body.read_u32(c)
    sections.push(Section::{
      name: sect_name,
      segment_name: seg_name,
      addr,
      size,
      file_offset: file_off,
      align,
      reloc_offset: reloff,
      nreloc,
      flags: sflags,
    })
    at = at + 80L
  }
  Segment::{
    name,
    vmaddr,
    vmsize,
    file_offset,
    file_size,
    init_prot: init_prot.to_int().reinterpret_as_uint(),
    nsects,
    flags,
    sections,
  }
}

///|
/// Finds a section by names. The segment name is matched as well because
/// `__text` exists in more than one segment across formats.
pub fn find_section(
  segs : Array[Segment],
  segment_name : String,
  section_name : String,
) -> Section? {
  for seg in segs {
    if seg.name != segment_name {
      continue
    }
    for s in seg.sections {
      if s.name == section_name {
        return Some(s)
      }
    }
  }
  None
}

///|
/// Translates a virtual address to a file offset.
///
/// Returns `None` for addresses in a segment's zero-fill tail, which occupies
/// memory but no bytes on disk, and `None` for addresses outside every segment.
pub fn file_offset_of_address(segs : Array[Segment], addr : Int64) -> Int64? {
  for seg in segs {
    if !seg.contains_address(addr) {
      continue
    }
    let delta = addr - seg.vmaddr
    if delta >= seg.file_size {
      return None
    }
    return Some(seg.file_offset + delta)
  }
  None
}
