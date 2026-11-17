// Apple's DER encoding of a property list.
//
// `CSMAGIC_EMBEDDED_DER_ENTITLEMENTS` (slot 7) does not hold an XML plist. It
// holds a property list encoded as ASN.1 DER with Apple's own tag assignments:
// the outer element is an application-class constructed tag 16 carrying a
// version integer and then the value, a dictionary is context-class constructed
// tag 16 whose children are SEQUENCE-wrapped key/value pairs, and an array is
// an ordinary SEQUENCE. The universal tags are the usual ones — BOOLEAN,
// INTEGER, UTF8String, OCTET STRING.
//
// Everything below is checked against the buffer. A DER plist that does not
// decode completely raises rather than returning a partial dictionary, because
// a caller reading entitlements is usually deciding whether to trust a build
// artifact and half a dictionary is the wrong answer to give it.

///|
/// The universal tag of a BOOLEAN.
pub const TAG_BOOLEAN : UInt32 = 0x01

///|
/// The universal tag of an INTEGER.
pub const TAG_INTEGER : UInt32 = 0x02

///|
/// Apple's tag for a whole DER-encoded plist: application class, constructed,
/// tag number 16.
pub const TAG_PLIST : UInt32 = 0x70

///|
/// Apple's tag for a dictionary: context class, constructed, tag number 16.
///
/// A dictionary's children are SEQUENCEs, each holding a key string and a
/// value. DER requires the members of a SET to be sorted, and Apple sorts these
/// by key, so the decoded order is stable across rebuilds.
pub const TAG_PLIST_DICT : UInt32 = 0xB0

///|
/// The deepest nesting this decoder accepts.
///
/// A plist is the one structure in a code signature whose shape is attacker
/// controlled and recursive, so the recursion needs a bound that does not
/// depend on the buffer being well formed.
const PLIST_MAX_DEPTH : Int32 = 64

///|
/// A decoded property list value.
///
/// The variants correspond one-to-one with the value types an entitlement file
/// may contain. `Date` is absent because Apple never encodes one here; a
/// plist that contains one is rejected rather than coerced into a string.
pub(all) enum Plist {
  /// `<true/>` or `<false/>`.
  Bool(Bool)
  /// `<integer>`, sign-extended to 64 bits.
  Int(Int64)
  /// `<string>`.
  Str(String)
  /// `<data>`, as the raw bytes.
  Data(Bytes)
  /// `<array>`, in encoded order.
  Array(Array[Plist])
  /// A `<dict>`; keys are in encoded order, which DER requires to be sorted.
  Dict(Array[(String, Plist)])
}

///|
/// Looks a key up in a dictionary.
///
/// Returns `None` for a non-dictionary, so a caller can chain lookups without
/// matching on the variant at every level.
pub fn Plist::get(self : Plist, key : String) -> Plist? {
  match self {
    Dict(entries) => {
      for entry in entries {
        let (k, v) = entry
        if k == key {
          return Some(v)
        }
      }
      None
    }
    _ => None
  }
}

///|
/// Decodes a DER-encoded property list.
///
/// Accepts both the wrapped form Apple writes (a `TAG_PLIST` element holding a
/// version integer and the value) and a bare value, because the tag is not
/// always present in blobs produced by older toolchains.
pub fn decode_der_plist(bytes : Bytes) -> Plist raise MachscopeError {
  let limit = bytes.length().to_int64()
  let top = read_element(bytes, 0L, limit)
  if top.tag == TAG_PLIST {
    let kids = children(bytes, top)
    if kids.length() != 2 {
      raise Inconsistent(
        what="DER plist",
        detail="wrapper must hold a version and one value",
      )
    }
    let version = plist_value(bytes, kids[0], 0)
    if version is Int(v) && v != 1L {
      raise BadValue(field="DER plist version", value=v)
    }
    return plist_value(bytes, kids[1], 0)
  }
  plist_value(bytes, top, 0)
}

///|
/// Decodes one value, dispatching on its tag.
///
/// `depth` counts nesting from the outermost element and is what keeps a plist
/// full of arrays from exhausting the call stack.
fn plist_value(
  bytes : Bytes,
  el : DerElement,
  depth : Int32,
) -> Plist raise MachscopeError {
  if depth > PLIST_MAX_DEPTH {
    raise LimitExceeded(
      what="DER plist nesting",
      limit=PLIST_MAX_DEPTH.to_int64(),
    )
  }
  match el.tag {
    TAG_BOOLEAN => {
      if el.content_end - el.content_start != 1L {
        raise BadValue(
          field="DER boolean length",
          value=el.content_end - el.content_start,
        )
      }
      Bool(bytes.at(el.content_start.to_int()).to_int() != 0)
    }
    TAG_INTEGER => Int(plist_integer(bytes, el))
    TAG_UTF8 => Str(plist_string(bytes, el))
    TAG_OCTET_STRING => Data(plist_bytes(bytes, el))
    TAG_SEQUENCE => {
      let out : Array[Plist] = []
      for child in children(bytes, el) {
        out.push(plist_value(bytes, child, depth + 1))
      }
      Array(out)
    }
    TAG_PLIST_DICT => {
      let out : Array[(String, Plist)] = []
      for pair in children(bytes, el) {
        if pair.tag != TAG_SEQUENCE {
          raise BadValue(field="DER dict entry tag", value=pair.tag.to_int64())
        }
        let members = children(bytes, pair)
        if members.length() != 2 {
          raise Inconsistent(
            what="DER dict entry",
            detail="expected exactly a key and a value",
          )
        }
        if members[0].tag != TAG_UTF8 {
          raise BadValue(
            field="DER dict key tag",
            value=members[0].tag.to_int64(),
          )
        }
        out.push(
          (
            plist_string(bytes, members[0]),
            plist_value(bytes, members[1], depth + 1),
          ),
        )
      }
      Dict(out)
    }
    _ => raise Unsupported(what="DER plist value tag \{el.tag.to_int64()}")
  }
}

///|
/// Reads an INTEGER's content as a big-endian two's-complement value.
///
/// DER does not pad to a fixed width, so an integer occupies as few bytes as it
/// can; a negative value is sign-extended from its own most significant bit.
fn plist_integer(bytes : Bytes, el : DerElement) -> Int64 raise MachscopeError {
  let n = el.content_end - el.content_start
  if n == 0L {
    return 0L
  }
  if n > 8L {
    raise LimitExceeded(what="DER integer width", limit=8L)
  }
  let mut v = 0L
  for i in 0..<n.to_int() {
    v = (v << 8) | bytes.at(el.content_start.to_int() + i).to_int().to_int64()
  }
  // Sign-extend when the top bit of the encoded width is set.
  let bits = n * 8L
  if bits < 64L {
    let top_bit = 1L << (bits - 1).to_int()
    if (v & top_bit) != 0L {
      v = v - (top_bit << 1)
    }
  }
  v
}

///|
/// Decodes a UTF8String's content.
fn plist_string(bytes : Bytes, el : DerElement) -> String raise MachscopeError {
  let raw = plist_bytes(bytes, el)
  @utf8.decode(raw) catch {
    _ => raise BadName(offset=el.content_start)
  }
}

///|
/// Copies an element's content range out of the buffer.
fn plist_bytes(bytes : Bytes, el : DerElement) -> Bytes raise MachscopeError {
  let n = el.content_end - el.content_start
  if n < 0L {
    raise Inconsistent(
      what="DER element",
      detail="content range runs backwards",
    )
  }
  let out = Buffer::Buffer()
  for i in 0..<n.to_int() {
    out.write_byte(bytes.at(el.content_start.to_int() + i))
  }
  out.to_bytes()
}

///|
/// Renders a plist as JSON.
///
/// A `Data` value becomes a hex string rather than an array of numbers: the
/// entitlement payloads that carry binary data are hashes, and a hash is easier
/// to compare against `codesign` output as hex than as 32 array elements.
pub fn Plist::to_json(self : Plist) -> Json {
  match self {
    Bool(b) => Json::boolean(b)
    Int(v) => Json::number(v.to_double())
    Str(s) => Json::string(s)
    Data(d) => Json::string(hex_bytes(d))
    Array(items) => {
      let out : Array[Json] = []
      for item in items {
        out.push(item.to_json())
      }
      Json::array(out)
    }
    Dict(entries) => {
      let fields : Map[String, Json] = Map([])
      for entry in entries {
        let (k, v) = entry
        fields[k] = v.to_json()
      }
      Json::object(fields)
    }
  }
}

///|
/// Formats bytes as lowercase hex without separators.
fn hex_bytes(bytes : Bytes) -> String {
  let digits = "0123456789abcdef"
  let buf = StringBuilder()
  for i in 0..<bytes.length() {
    let b = bytes.at(i).to_int()
    buf.write_char(digits.code_unit_at((b >> 4) & 0xF).unsafe_to_char())
    buf.write_char(digits.code_unit_at(b & 0xF).unsafe_to_char())
  }
  buf.to_string()
}
