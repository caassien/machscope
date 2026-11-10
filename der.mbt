// A minimal ASN.1 reader: tags, lengths and children.
//
// This is the framing layer `plist.mbt` builds on when it decodes the DER
// property list Apple stores in the entitlements slot. It implements exactly
// what that decoding needs — definite lengths in short and long form, the
// indefinite form BER permits, and the child ranges of a constructed element —
// and refuses anything it does not understand rather than guessing.
//
// It is not a general ASN.1 library and does not interpret tags: which tag
// means "dictionary" is a question about Apple's plist encoding, and that
// answer lives in `plist.mbt`, not here.

///|
/// One DER element: its tag, its content range and the offset just past it.
pub(all) struct DerElement {
  /// The identifier octet. Only single-byte tags are decoded, which covers
  /// every tag that appears in a property list.
  tag : UInt32
  /// First byte of the content.
  content_start : Int64
  /// One past the last content byte.
  content_end : Int64
  /// One past the last byte of the whole element, header included.
  next : Int64
}

///|
/// The universal tag number for a SEQUENCE or SEQUENCE OF.
///
/// In Apple's plist encoding a SEQUENCE is an array; a dictionary is a
/// context-class tag instead, defined in `plist.mbt`.
pub const TAG_SEQUENCE : UInt32 = 0x30

///|
/// The universal tag number for an OCTET STRING.
pub const TAG_OCTET_STRING : UInt32 = 0x04

///|
/// The universal tag number for a UTF8String.
pub const TAG_UTF8 : UInt32 = 0x0C

///|
/// Reads one element's header and content range.
///
/// Handles both definite lengths (short and long form) and the indefinite form
/// BER permits, which ends at a zero-length end-of-contents marker.
pub fn read_element(
  bytes : Bytes,
  offset : Int64,
  limit : Int64,
) -> DerElement raise MachscopeError {
  if offset + 2L > limit {
    raise UnexpectedEnd(offset~, needed=2L, available=limit - offset)
  }
  let tag = bytes.at(offset.to_int()).to_int().reinterpret_as_uint()
  let first_len = bytes.at(offset.to_int() + 1).to_int()
  let mut cursor = offset + 2L
  let content_len : Int64? = if first_len < 0x80 {
    Some(first_len.to_int64())
  } else if first_len == 0x80 {
    None // indefinite: caller walks children until end-of-contents
  } else {
    let n = first_len & 0x7F
    if n > 4 {
      raise Unsupported(what="DER length longer than 32 bits")
    }
    let mut len = 0L
    for _ in 0..<n {
      if cursor + 1L > limit {
        raise UnexpectedEnd(offset=cursor, needed=1L, available=limit - cursor)
      }
      len = (len << 8) | bytes.at(cursor.to_int()).to_int().to_int64()
      cursor = cursor + 1L
    }
    Some(len)
  }
  match content_len {
    Some(len) => {
      if cursor + len > limit {
        raise OutOfBounds(what="DER content", offset=cursor, size=len, limit~)
      }
      DerElement::{
        tag,
        content_start: cursor,
        content_end: cursor + len,
        next: cursor + len,
      }
    }
    None => {
      // Walk children until the two zero bytes that close the element.
      let mut at = cursor
      let mut end = -1L
      while at + 2L <= limit {
        let t = bytes.at(at.to_int()).to_int()
        let l = bytes.at(at.to_int() + 1).to_int()
        if t == 0 && l == 0 {
          end = at + 2L
          break
        }
        let child = read_element(bytes, at, limit)
        at = child.next
      }
      if end < 0L {
        raise UnexpectedEnd(offset~, needed=2L, available=limit - at)
      }
      DerElement::{ tag, content_start: cursor, content_end: at, next: end, }
    }
  }
}

///|
/// Collects the immediate children of a constructed element.
///
/// Indefinite-length parents have their children walked until the
/// end-of-contents marker; definite-length parents stop at their declared end.
pub fn children(
  bytes : Bytes,
  parent : DerElement,
) -> Array[DerElement] raise MachscopeError {
  let out : Array[DerElement] = []
  let mut at = parent.content_start
  while at < parent.content_end {
    // Skip the end-of-contents marker of an indefinite element.
    if parent.content_end - at >= 2L {
      let t = bytes.at(at.to_int()).to_int()
      let l = bytes.at(at.to_int() + 1).to_int()
      if t == 0 && l == 0 {
        break
      }
    }
    let child = read_element(bytes, at, parent.content_end)
    out.push(child)
    at = child.next
  }
  out
}
