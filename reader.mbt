// Bounds-checked reading of primitive values.
//
// Every function here takes the current cursor and returns the decoded value
// plus the advanced cursor, so a caller can never observe a partially consumed
// field. Nothing in this file indexes a buffer directly; all access goes
// through `Bounds` so that a truncated file produces `UnexpectedEnd` instead of
// an out-of-range read.

///|
/// Reinterprets the low 32 bits of an `Int64` as an unsigned word.
///
/// Used when a value was accumulated in a wider type to keep the high bit from
/// turning negative; the mask makes the truncation explicit.
fn u32_of_int64(v : Int64) -> UInt32 {
  (v & 0xFFFF_FFFFL).to_int().reinterpret_as_uint()
}

///|
/// A buffer together with the range of it that is legal to read.
///
/// `start` and `limit` are absolute file offsets, which lets a slice of a fat
/// binary be handed to the parser without copying: the slice's `Bounds` covers
/// its own byte range and every error message still reports a file offset.
pub(all) struct Bounds {
  /// Bytes of the file.
  bytes : Bytes
  /// First readable offset; usually 0, non-zero for a slice inside a fat file.
  start : Int64
  /// One past the last readable offset.
  limit : Int64
}

///|
/// Wraps a whole buffer as readable from offset 0 to its length.
pub fn Bounds::of_bytes(bytes : Bytes) -> Bounds {
  Bounds::{ bytes, start: 0L, limit: bytes.length().to_int64(), }
}

///|
/// Number of readable bytes.
pub fn Bounds::length(self : Bounds) -> Int64 {
  self.limit - self.start
}

///|
/// Fails unless `[offset, offset + size)` lies inside the readable range.
///
/// Parsers call this before interpreting a length field that came from the
/// file, so a corrupt length is reported as `OutOfBounds` with the offending
/// field name rather than being trusted.
pub fn Bounds::require(
  self : Bounds,
  offset : Int64,
  size : Int64,
  what : String,
) -> Unit raise MachscopeError {
  if size < 0L {
    raise OutOfBounds(what~, offset~, size~, limit=self.limit)
  }
  if offset < self.start || offset > self.limit || size > self.limit - offset {
    raise OutOfBounds(what~, offset~, size~, limit=self.limit)
  }
}

///|
/// Returns the byte at an absolute offset after checking that it is readable.
fn Bounds::byte(self : Bounds, offset : Int64) -> Byte raise MachscopeError {
  self.require(offset, 1L, "byte")
  self.bytes.at(offset.to_int())
}

///|
/// Decodes an unsigned 8-bit integer.
pub fn Bounds::read_u8(
  self : Bounds,
  cur : Cursor,
) -> (UInt32, Cursor) raise MachscopeError {
  let v = self.byte(cur.pos).to_int().reinterpret_as_uint()
  (v, Cursor::{ pos: cur.pos + 1L, endian: cur.endian, })
}

///|
/// Decodes a signed 8-bit integer, sign-extending into `Int64`.
pub fn Bounds::read_i8(
  self : Bounds,
  cur : Cursor,
) -> (Int64, Cursor) raise MachscopeError {
  let raw = self.byte(cur.pos).to_int()
  let signed = if raw >= 0x80 { raw - 0x100 } else { raw }
  (signed.to_int64(), Cursor::{ pos: cur.pos + 1L, endian: cur.endian, })
}

///|
/// Decodes an unsigned 16-bit integer in the cursor's byte order.
pub fn Bounds::read_u16(
  self : Bounds,
  cur : Cursor,
) -> (UInt32, Cursor) raise MachscopeError {
  self.require(cur.pos, 2L, "u16")
  let b0 = self.bytes.at(cur.pos.to_int()).to_int()
  let b1 = self.bytes.at(cur.pos.to_int() + 1).to_int()
  let v = match cur.endian {
    Little => b0 | (b1 << 8)
    Big => (b0 << 8) | b1
  }
  (v.reinterpret_as_uint(), Cursor::{ pos: cur.pos + 2L, endian: cur.endian, })
}

///|
/// Decodes an unsigned 32-bit integer in the cursor's byte order.
///
/// Accumulated as `Int64` so that a value with the high bit set does not turn
/// negative before it is reinterpreted as `UInt32`.
pub fn Bounds::read_u32(
  self : Bounds,
  cur : Cursor,
) -> (UInt32, Cursor) raise MachscopeError {
  self.require(cur.pos, 4L, "u32")
  let base = cur.pos.to_int()
  let b0 = self.bytes.at(base).to_int().to_int64()
  let b1 = self.bytes.at(base + 1).to_int().to_int64()
  let b2 = self.bytes.at(base + 2).to_int().to_int64()
  let b3 = self.bytes.at(base + 3).to_int().to_int64()
  let v = match cur.endian {
    Little => b0 | (b1 << 8) | (b2 << 16) | (b3 << 24)
    Big => (b0 << 24) | (b1 << 16) | (b2 << 8) | b3
  }
  (u32_of_int64(v), Cursor::{ pos: cur.pos + 4L, endian: cur.endian, })
}

///|
/// Decodes a signed 32-bit integer, sign-extending into `Int64`.
///
/// Used for fields such as `cputype`, which the loader treats as signed and
/// which must round-trip for unknown architectures.
pub fn Bounds::read_i32(
  self : Bounds,
  cur : Cursor,
) -> (Int64, Cursor) raise MachscopeError {
  let (raw, next) = self.read_u32(cur)
  let v = raw.to_int64()
  let signed = if v >= 0x8000_0000L { v - 0x1_0000_0000L } else { v }
  (signed, next)
}

///|
/// Decodes an unsigned 64-bit integer in the cursor's byte order.
///
/// Accumulated as `Int64` so that all 64 bits round-trip; callers that need
/// the unsigned interpretation mask at the use site.
pub fn Bounds::read_u64(
  self : Bounds,
  cur : Cursor,
) -> (Int64, Cursor) raise MachscopeError {
  self.require(cur.pos, 8L, "u64")
  let (lo, next) = self.read_u32(cur)
  let (hi, next) = self.read_u32(next)
  let v = match cur.endian {
    Little => (hi.to_int64() << 32) | (lo.to_int64() & 0xFFFF_FFFFL)
    Big => (lo.to_int64() << 32) | (hi.to_int64() & 0xFFFF_FFFFL)
  }
  (v, next)
}

///|
/// Reads `n` bytes starting at `offset`, copying them into a fresh buffer.
pub fn Bounds::slice(
  self : Bounds,
  offset : Int64,
  n : Int64,
  what : String,
) -> Bytes raise MachscopeError {
  self.require(offset, n, what)
  let out = Buffer::Buffer(size_hint=n.to_int())
  for i in 0..<n.to_int() {
    out.write_byte(self.bytes.at(offset.to_int() + i))
  }
  out.to_bytes()
}

///|
/// Reads a fixed-width, zero-padded NUL-terminated name field, e.g. the
/// 16-byte `segname` of a segment command.
///
/// Bytes after the first NUL are ignored, which is what the loader does: the
/// remainder of the field is padding and not necessarily zeroed.
pub fn Bounds::fixed_name(
  self : Bounds,
  offset : Int64,
  width : Int64,
  what : String,
) -> String raise MachscopeError {
  self.require(offset, width, what)
  let buf = Buffer::Buffer(size_hint=width.to_int())
  for i in 0..<width.to_int() {
    let b = self.bytes.at(offset.to_int() + i)
    if b.to_int() == 0 {
      break
    }
    buf.write_byte(b)
  }
  buf.to_bytes().to_unchecked_string()
}
