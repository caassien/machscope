// A minimal DER/BER reader, used to reach the entitlements inside a code
// signature.
//
// Apple wraps entitlements in a PKCS#7 `SignedData` structure: the entitlement
// plist is not stored as a separate blob but as an octet string inside an
// attribute. Reaching it means walking ASN.1, so this file implements exactly
// the subset that walk needs — definite and indefinite lengths, the universal
// tags for sequences, octet strings and OIDs — and refuses everything else
// rather than guessing.
//
// Not a general ASN.1 library. It returns the payload or an error, never
// partial DER.

///|
/// One DER element: its tag, its content range and the offset just past it.
pub(all) struct DerElement {
  /// The identifier octet. Only single-byte tags are decoded, which covers
  /// every tag that appears in a code signature.
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
pub const TAG_SEQUENCE : UInt32 = 0x30

///|
/// The universal tag number for a SET or SET OF.
pub const TAG_SET : UInt32 = 0x31

///|
/// The universal tag number for an OCTET STRING.
pub const TAG_OCTET_STRING : UInt32 = 0x04

///|
/// The universal tag number for an OBJECT IDENTIFIER.
pub const TAG_OID : UInt32 = 0x06

///|
/// The universal tag number for a UTF8String.
pub const TAG_UTF8 : UInt32 = 0x0C

///|
/// The tag Apple uses for a context-specific constructed element (0xA0).
pub const TAG_CTX_0 : UInt32 = 0xA0

///|
/// The second context-specific constructed tag in the CMS layout (0xA1).
pub const TAG_CTX_1 : UInt32 = 0xA1

///|
/// Encodes a string as UTF-8 bytes.
///
/// The DER payloads this module handles are ASCII identifiers and plist text,
/// so a byte-for-byte widening is exact; `@encoding/utf8` would be the general
/// answer but pulling in the encoder for this would be heavier than the need.
fn utf8_of(s : String) -> Bytes {
  let buf = Buffer()
  for i in 0..<s.length() {
    buf.write_byte(s.code_unit_at(i).to_int().to_byte())
  }
  buf.to_bytes()
}

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

///|
/// Reads an OCTET STRING's payload.
///
/// Concatenates the fragments of a constructed octet string, which is the form
/// a large entitlement plist takes.
pub fn octet_string(
  bytes : Bytes,
  el : DerElement,
) -> Bytes raise MachscopeError {
  let out = StringBuilder()
  if el.tag == TAG_OCTET_STRING && el.content_start + 2L <= el.content_end {
    // Constructed form: children are octet strings.
    let first = bytes.at(el.content_start.to_int()).to_int()
    if first == 0x04 {
      // Ambiguous: a primitive octet string whose first byte happens to be
      // 0x04 starts with a tag byte too. Distinguish by re-reading the
      // element and checking whether its declared content length matches.
      let as_primitive_len = el.content_end - el.content_start
      let inner = read_element(bytes, el.content_start, el.content_end)
      if inner.content_end != el.content_start + as_primitive_len {
        for part in children(bytes, el) {
          for i in 0..<(part.content_end - part.content_start).to_int() {
            out.write_char(
              bytes.at((part.content_start + i.to_int64()).to_int()).to_char(),
            )
          }
        }
        return utf8_of(out.to_string())
      }
    }
  }
  for i in 0..<(el.content_end - el.content_start).to_int() {
    out.write_char(
      bytes.at((el.content_start + i.to_int64()).to_int()).to_char(),
    )
  }
  utf8_of(out.to_string())
}

///|
/// Finds a `SignedData` element inside a code-signature blob.
///
/// The blob is a DER `ContentInfo`: a SEQUENCE holding an OID and a
/// context-specific wrapper around the `SignedData`. The walk returns the
/// SignedData element so its nested attributes can be searched.
pub fn find_signed_data(bytes : Bytes) -> DerElement raise MachscopeError {
  let top = read_element(bytes, 0L, bytes.length().to_int64())
  if top.tag != TAG_SEQUENCE {
    raise BadValue(field="ContentInfo tag", value=top.tag.to_int64())
  }
  for child in children(bytes, top) {
    if child.tag == TAG_SEQUENCE {
      // Some blobs wrap SignedData directly in the second child.
      return child
    }
    if child.tag == TAG_CTX_0 || child.tag == TAG_CTX_1 {
      for inner in children(bytes, child) {
        if inner.tag == TAG_SEQUENCE {
          return inner
        }
      }
    }
  }
  raise Inconsistent(what="PKCS#7 blob", detail="no SignedData sequence found")
}
