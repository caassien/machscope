// machscope — Mach-O and DWARF inspection in pure MoonBit.
//
// The public entry points live in `parser.mbt`. This file holds the shared
// vocabulary: errors, byte-order helpers and the small cursor type that every
// parser in the module reads through.

///|
/// Every way a Mach-O or DWARF buffer can be rejected.
///
/// Requests are never answered with a partially-parsed structure: a malformed
/// image surfaces as one of these variants instead of an out-of-bounds read.
/// Offsets in the payloads are absolute file offsets so that a caller can point
/// at the exact bytes that failed.
pub(all) suberror MachscopeError {
  /// The buffer ended before a structure could be read completely.
  UnexpectedEnd(offset~ : Int64, needed~ : Int64, available~ : Int64)
  /// The magic number does not belong to any format this library understands.
  BadMagic(magic~ : UInt32)
  /// A field that must take one of a small set of values holds something else.
  BadValue(field~ : String, value~ : Int64)
  /// A size or offset would address bytes outside the buffer.
  OutOfBounds(what~ : String, offset~ : Int64, size~ : Int64, limit~ : Int64)
  /// A name field was not valid UTF-8 or contained a NUL inside its bounds.
  BadName(offset~ : Int64)
  /// A structure is well-formed on its own but contradicts another structure.
  Inconsistent(what~ : String, detail~ : String)
  /// A limit on nesting, entry count or decoded size was exceeded.
  LimitExceeded(what~ : String, limit~ : Int64)
  /// A code path this version does not implement was reached.
  Unsupported(what~ : String)
}

///|
/// Renders an error as a single line naming the field and the offset that
/// failed.
///
/// The CLI prints this directly, and it is what a caller sees when a corrupt
/// file is rejected: the message has to point at a byte, not just say
/// "malformed".
pub impl Show for MachscopeError with fn output(self, logger) {
  let text = match self {
    UnexpectedEnd(offset~, needed~, available~) =>
      "unexpected end at offset \{offset}: needed \{needed} bytes, \{available} available"
    BadMagic(magic~) => "not a Mach-O file: magic 0x\{magic.to_int64()}"
    BadValue(field~, value~) => "bad value for \{field}: \{value}"
    OutOfBounds(what~, offset~, size~, limit~) =>
      "\{what} at offset \{offset}+\{size} exceeds limit \{limit}"
    BadName(offset~) => "invalid name field at offset \{offset}"
    Inconsistent(what~, detail~) => "\{what} is inconsistent: \{detail}"
    LimitExceeded(what~, limit~) => "\{what} exceeds the limit of \{limit}"
    Unsupported(what~) => "unsupported: \{what}"
  }
  logger.write_string(text)
}

///|
/// Exposes the error message as a plain method.
pub extend MachscopeError with Show::{to_string, output}

///|
/// Byte order of the file being read.
///
/// Mach-O files record their own endianness in the magic number; fat headers
/// and DWARF sections inherit the order of the slice or compilation unit that
/// contains them.
pub(all) enum Endian {
  /// Least significant byte first (x86, x86_64, arm, arm64).
  Little
  /// Most significant byte first (legacy PowerPC and m68k images).
  Big
}

///|
/// Renders the byte order as the word used by the Mach-O headers.
impl Show for Endian with fn to_string(self) {
  match self {
    Little => "little-endian"
    Big => "big-endian"
  }
}

///|
/// The byte order as a short tag, for JSON and CLI output.
pub fn Endian::tag(self : Endian) -> String {
  match self {
    Little => "le"
    Big => "be"
  }
}

///|
/// Position of a byte within the buffer, together with the byte order used to
/// decode multi-byte integers at that position.
///
/// A `Cursor` is a value, not a view: advancing returns a new cursor and never
/// touches the shared buffer, so the same source bytes can be read by several
/// parsers without copying.
pub(all) struct Cursor {
  /// Index of the next byte to be read.
  pos : Int64
  /// Byte order applied by `read_u16`, `read_u32` and `read_u64`.
  endian : Endian
}
