// Mach-O container parsing: magic numbers, fat (universal) binaries, the
// `mach_header` of a thin image and the generic `load_command` framing.
//
// Parsing happens in two stages. `parse_slice` validates the header and walks
// the load-command table, checking every offset and size; `commands.mbt` then
// interprets individual commands.

///|
/// The four byte orders and word sizes a Mach-O image can be wrapped in.
///
/// The magic number is read as a 32-bit little-endian word first; a value that
/// matches none of these four is not a Mach-O file at all.
pub(all) enum MachKind {
  /// 64-bit little-endian image (`MH_MAGIC_64`).
  Mach64
  /// 32-bit little-endian image (`MH_MAGIC`).
  Mach32
  /// 64-bit big-endian image (`MH_CIGAM_64`), legacy PowerPC64.
  Mach64Be
  /// 32-bit big-endian image (`MH_CIGAM`), legacy PowerPC.
  Mach32Be
}

///|
/// `MH_MAGIC_64`, read little-endian: bytes `cf fa ed fe`.
const MAGIC_64 : UInt32 = 0xFEED_FACF

///|
/// `MH_MAGIC`, read little-endian: bytes `ce fa ed fe`.
const MAGIC_32 : UInt32 = 0xFEED_FACE

///|
/// `FAT_MAGIC`, read big-endian: bytes `ca fe ba be`.
const FAT_MAGIC : UInt32 = 0xCAFE_BABE

///|
/// `FAT_MAGIC_64`, read big-endian: bytes `ca fe ba bf`.
const FAT_MAGIC_64 : UInt32 = 0xCAFE_BABF

///|
/// Renders the kind as its header identifier, which is the name `file(1)`
/// prints for the same image.
impl Show for MachKind with fn to_string(self) {
  match self {
    Mach64 => "MH_MAGIC_64"
    Mach32 => "MH_MAGIC"
    Mach64Be => "MH_CIGAM_64"
    Mach32Be => "MH_CIGAM"
  }
}

///|
/// Word size of a kind, in bytes.
pub fn MachKind::pointer_size(self : MachKind) -> Int32 {
  match self {
    Mach64 | Mach64Be => 8
    Mach32 | Mach32Be => 4
  }
}

///|
/// Byte order of a kind.
pub fn MachKind::endian(self : MachKind) -> Endian {
  match self {
    Mach64 | Mach32 => Little
    Mach64Be | Mach32Be => Big
  }
}

///|
/// Size of `mach_header` / `mach_header_64` in bytes.
pub fn MachKind::header_size(self : MachKind) -> Int64 {
  match self {
    Mach64 | Mach64Be => 32L
    Mach32 | Mach32Be => 28L
  }
}

///|
/// Resolves a magic word to a kind, or `None` if it is not a thin Mach-O image.
fn kind_of_magic(magic : UInt32) -> MachKind? {
  match magic {
    MAGIC_64 => Some(Mach64)
    MAGIC_32 => Some(Mach32)
    // Reversed on disk: a big-endian image read as little-endian.
    0xCF_FA_ED_FE => Some(Mach64Be)
    0xCE_FA_ED_FE => Some(Mach32Be)
    _ => None
  }
}

///|
/// The `mach_header` fields that are meaningful independent of word size.
///
/// Field names follow `<mach-o/loader.h>` so that a reader can compare them
/// against the C definition without a mapping table.
pub(all) struct MachHeader {
  /// Word size and byte order of the image.
  kind : MachKind
  /// `cputype`, signed because the loader keeps it signed.
  cpu_type : Int64
  /// `cpusubtype`, with the capability bits still attached.
  cpu_subtype : Int64
  /// `filetype`: 2 executable, 6 dylib, 8 bundle, 1 object, ...
  file_type : UInt32
  /// Number of load commands that follow the header.
  ncmds : UInt32
  /// Total byte size of the load-command table.
  sizeofcmds : UInt32
  /// `MH_*` flags bitfield.
  flags : UInt32
  /// Reserved word present only in the 64-bit header.
  reserved : UInt32
}

///|
/// Mask selecting the capability bits of a `cpusubtype` field.
///
/// `<mach-o/machine.h>` defines `CPU_SUBTYPE_MASK` as `0xff000000`: the low 24
/// bits identify the subtype, the high 8 bits carry capabilities such as
/// pointer authentication for arm64e. Both the thin header and the fat
/// architecture table store the combined value, so callers that want to compare
/// against constants like `CPU_SUBTYPE_ARM64E` must mask first.
pub const CPU_SUBTYPE_MASK : Int64 = 0xFF00_0000L

///|
/// Formats an integer as lowercase hexadecimal.
///
/// Lives in the library rather than the CLI because every caller that prints an
/// offset or a flags word needs it, and because it is the one conversion whose
/// output the tests can assert against `otool`.
pub fn hex(v : Int64) -> String {
  if v == 0L {
    return "0"
  }
  let digits = "0123456789abcdef"
  let raw : Array[Char] = Array::make(16, '0')
  let mut n = v
  let mut i = 15
  while i >= 0 {
    let d = (n & 0xFL).to_int()
    raw[i] = digits.code_unit_at(d).unsafe_to_char()
    n = n >> 4
    i = i - 1
  }
  let buf = StringBuilder()
  let mut wrote = false
  for j in 0..<16 {
    let c = raw[j]
    if !wrote && c == '0' {
      continue
    }
    wrote = true
    buf.write_char(c)
  }
  buf.to_string()
}

///|
/// The low 24 bits of a `cpusubtype`: the subtype without capability bits.
pub fn subtype_base(raw : Int64) -> Int64 {
  raw & 0xFF_FFFFL
}

///|
/// The high 8 bits of a `cpusubtype`: pointer authentication and similar
/// capability flags.
pub fn subtype_capabilities(raw : Int64) -> Int64 {
  (raw & CPU_SUBTYPE_MASK) >> 24
}

///|
/// The header's `cpusubtype` with capability bits removed.
pub fn MachHeader::cpu_subtype_base(self : MachHeader) -> Int64 {
  subtype_base(self.cpu_subtype)
}

///|
/// The header's capability flags, from the high byte of `cpusubtype`.
pub fn MachHeader::cpu_capabilities(self : MachHeader) -> Int64 {
  subtype_capabilities(self.cpu_subtype)
}

///|
/// A load command as framed by the parser, before its payload is interpreted.
pub(all) struct RawCommand {
  /// `cmd` field.
  cmd : UInt32
  /// `cmdsize` field, as recorded in the file.
  size : UInt32
  /// Absolute file offset of the command's first byte.
  offset : Int64
}

///|
/// A validated thin Mach-O image: the header, its load-command framing and the
/// byte range the slice occupies inside the file it came from.
pub(all) struct MachSlice {
  /// Parsed header.
  header : MachHeader
  /// Load commands in file order, each already bounds-checked as a whole.
  commands : Array[RawCommand]
  /// Readable range for this slice; absolute offsets into the original file.
  bounds : Bounds
}

///|
/// Result of opening a file: either one thin image or the slices of a fat one.
pub(all) enum MachFile {
  /// A thin Mach-O image occupying the whole file.
  Thin(MachSlice)
  /// A universal binary and the architecture of each of its slices.
  Fat(Array[FatSlice])
}

///|
/// One entry of a fat binary's architecture table, with its slice parsed.
///
/// `FatArch` fields keep the names used in `<mach-o/fat.h>`.
pub(all) struct FatSlice {
  /// `cputype` from the architecture table.
  cpu_type : Int64
  /// `cpusubtype` from the architecture table.
  cpu_subtype : Int64
  /// Absolute offset of the slice inside the file.
  offset : Int64
  /// Byte size of the slice.
  size : Int64
  /// `align` field: the slice is 2^align aligned.
  align : UInt32
  /// The parsed slice, with its bounds restricted to `[offset, offset+size)`.
  image : MachSlice
}

///|
/// A one-line summary of the header, in the shape `file(1)` prints.
///
/// Used by the CLI's default output and by error reports, so that a user
/// looking at a failure knows which image the failure came from.
pub fn MachHeader::describe(self : MachHeader) -> String {
  let arch = match self.cpu_type {
    7L => "i386"
    0x0100_0007L => "x86_64"
    12L => "arm"
    0x0100_000CL => "arm64"
    18L => "ppc"
    0x0100_0018L => "ppc64"
    _ => "cpu=\{self.cpu_type}"
  }
  let kind = Show::to_string(self.kind)
  "\{arch} \{kind} (\{Show::to_string(self.kind.endian())}), subtype \{self.cpu_subtype_base()}, filetype \{self.file_type}, \{self.ncmds} commands, \{self.sizeofcmds} bytes"
}

///|
/// The architecture table entry's `cpusubtype` with capability bits removed.
pub fn FatSlice::cpu_subtype_base(self : FatSlice) -> Int64 {
  subtype_base(self.cpu_subtype)
}

///|
/// The architecture table entry's capability flags.
pub fn FatSlice::cpu_capabilities(self : FatSlice) -> Int64 {
  subtype_capabilities(self.cpu_subtype)
}

///|
/// Parses a header and its load-command framing at `offset` inside `bounds`.
///
/// Every command is checked to start and end inside the slice and inside the
/// declared `sizeofcmds` region; a command whose `cmdsize` is smaller than the
/// 8-byte generic header, or not a multiple of 4, makes the whole image
/// unreadable because the table cannot be walked any further.
pub fn parse_slice(
  bounds : Bounds,
  offset : Int64,
) -> MachSlice raise MachscopeError {
  let (magic, _) = bounds.read_u32(Cursor::{ pos: offset, endian: Little, })
  let kind = match kind_of_magic(magic) {
    Some(k) => k
    None => raise BadMagic(magic~)
  }
  let endian = kind.endian()
  let cur = Cursor::{ pos: offset, endian, }
  let (_, cur) = bounds.read_u32(cur)
  let (cpu_type, cur) = bounds.read_i32(cur)
  let (cpu_subtype, cur) = bounds.read_i32(cur)
  let (file_type, cur) = bounds.read_u32(cur)
  let (ncmds, cur) = bounds.read_u32(cur)
  let (sizeofcmds, cur) = bounds.read_u32(cur)
  let (flags, cur) = bounds.read_u32(cur)
  let (reserved, cur) = if kind.pointer_size() == 8 {
    bounds.read_u32(cur)
  } else {
    (0U, cur)
  }
  let header = MachHeader::{
    kind,
    cpu_type,
    cpu_subtype,
    file_type,
    ncmds,
    sizeofcmds,
    flags,
    reserved,
  }
  // The table must fit, and a command table cannot hold more entries than
  // there are 8-byte generic headers in it.
  bounds.require(cur.pos, sizeofcmds.to_int64(), "load commands")
  if ncmds.to_int64() * 8L > sizeofcmds.to_int64() {
    raise Inconsistent(
      what="load command table",
      detail="ncmds cannot fit in sizeofcmds",
    )
  }
  let table_end = cur.pos + sizeofcmds.to_int64()
  let commands : Array[RawCommand] = []
  let mut at = cur.pos
  for _ in 0..<ncmds.reinterpret_as_int() {
    if at + 8L > table_end {
      raise Inconsistent(
        what="load command table",
        detail="command starts past sizeofcmds",
      )
    }
    let (cmd, c1) = bounds.read_u32(Cursor::{ pos: at, endian, })
    let (size, _) = bounds.read_u32(c1)
    let size64 = size.to_int64()
    if size64 < 8L {
      raise BadValue(field="cmdsize", value=size64)
    }
    if size64 % 4L != 0L {
      raise BadValue(field="cmdsize alignment", value=size64)
    }
    if at + size64 > table_end {
      raise Inconsistent(
        what="load command table",
        detail="command extends past sizeofcmds",
      )
    }
    commands.push(RawCommand::{ cmd, size, offset: at, })
    at = at + size64
  }
  MachSlice::{ header, commands, bounds, }
}

///|
/// Opens a buffer as a Mach-O file, accepting both thin and fat images.
///
/// A fat image is parsed slice by slice; a slice that fails to parse makes the
/// whole call fail, because a universal binary with one unreadable
/// architecture cannot be reported as a usable universal binary.
pub fn parse(bytes : Bytes) -> MachFile raise MachscopeError {
  let bounds = Bounds::of_bytes(bytes)
  let (magic, _) = bounds.read_u32(Cursor::{ pos: 0L, endian: Big, })
  match magic {
    FAT_MAGIC => parse_fat(bounds, false)
    FAT_MAGIC_64 => parse_fat(bounds, true)
    _ => Thin(parse_slice(bounds, 0L))
  }
}

///|
/// Parses a fat architecture table and every slice it names.
///
/// `wide` selects the `fat_arch_64` layout, whose offset and size fields are
/// 64-bit; a 32-bit table is otherwise identical.
fn parse_fat(bounds : Bounds, wide : Bool) -> MachFile raise MachscopeError {
  let cur = Cursor::{ pos: 0L, endian: Big, }
  let (_, cur) = bounds.read_u32(cur) // magic, already matched
  let (nfat_arch, cur) = bounds.read_u32(cur)
  let entry_size = if wide { 32L } else { 20L }
  bounds.require(cur.pos, nfat_arch.to_int64() * entry_size, "fat arch table")
  let slices : Array[FatSlice] = []
  let mut at = cur.pos
  for _ in 0..<nfat_arch.reinterpret_as_int() {
    let c = Cursor::{ pos: at, endian: Big, }
    let (cpu_type, c) = bounds.read_i32(c)
    let (cpu_subtype, c) = bounds.read_i32(c)
    let (offset, c) = if wide {
      bounds.read_u64(c)
    } else {
      let (v, n) = bounds.read_u32(c)
      (v.to_int64(), n)
    }
    let (size, c) = if wide {
      bounds.read_u64(c)
    } else {
      let (v, n) = bounds.read_u32(c)
      (v.to_int64(), n)
    }
    let (align, _) = bounds.read_u32(c)
    bounds.require(offset, size, "fat slice")
    let slice_bounds = Bounds::{
      bytes: bounds.bytes,
      start: offset,
      limit: offset + size,
    }
    let image = parse_slice(slice_bounds, offset)
    slices.push(FatSlice::{ cpu_type, cpu_subtype, offset, size, align, image, })
    at = at + entry_size
  }
  Fat(slices)
}
