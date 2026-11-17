// Tests for the DER property-list decoder.
//
// The fixtures in `internal/fixtures/` are the authoritative inputs: they are
// real payloads `codesign` wrote, and `signature_wbtest.mbt` checks them
// against what `codesign -d --entitlements` prints. What these tests add is the
// machinery around that path — the shapes a hand-built buffer can reach and a
// real entitlement file never does, plus the JSON rendering the CLI prints.

///|
/// Builds a DER element with a definite length in short or long form.
fn der(tag : Int32, payload : Bytes) -> Bytes {
  let buf = Buffer()
  buf.write_byte(tag.to_byte())
  let n = payload.length()
  if n < 0x80 {
    buf.write_byte(n.to_byte())
  } else if n <= 0xFF {
    buf.write_byte(0x81)
    buf.write_byte(n.to_byte())
  } else {
    buf.write_byte(0x82)
    buf.write_byte((n >> 8).to_byte())
    buf.write_byte((n & 0xFF).to_byte())
  }
  for i in 0..<n {
    buf.write_byte(payload.at(i))
  }
  buf.to_bytes()
}

///|
/// Concatenates byte arrays.
fn cat(parts : Array[Bytes]) -> Bytes {
  let buf = Buffer()
  for p in parts {
    for i in 0..<p.length() {
      buf.write_byte(p.at(i))
    }
  }
  buf.to_bytes()
}

///|
/// Encodes an ASCII string as bytes.
fn ascii(s : String) -> Bytes {
  let buf = Buffer()
  for i in 0..<s.length() {
    buf.write_byte(s.code_unit_at(i).to_int().to_byte())
  }
  buf.to_bytes()
}

///|
/// Wraps a value the way Apple does: an application tag 0x70 holding a version
/// integer and then the value itself.
fn wrapped(value : Bytes) -> Bytes {
  der(0x70, cat([der(0x02, Bytes::from_array([b'\x01'])), value]))
}

///|
/// Builds one dictionary entry: a SEQUENCE of a key string and a value.
fn entry(key : String, value : Bytes) -> Bytes {
  der(0x30, cat([der(0x0C, ascii(key)), value]))
}

///|
/// Builds a dictionary from already-encoded entries.
fn dict(entries : Array[Bytes]) -> Bytes {
  der(0xB0, cat(entries))
}

///|
test "plist: each scalar type decodes to its own variant" {
  let b = wrapped(
    dict([
      entry("bool", der(0x01, Bytes::from_array([b'\xff']))),
      entry("int", der(0x02, Bytes::from_array([b'\x2a']))),
      entry("str", der(0x0C, ascii("hi"))),
      entry("data", der(0x04, Bytes::from_array([b'\x01', b'\x02']))),
    ]),
  )
  let p = decode_der_plist(b)
  inspect(p.get("bool") is Some(Bool(true)), content="true")
  inspect(p.get("int") is Some(Int(42)), content="true")
  inspect(p.get("str") is Some(Str("hi")), content="true")
  inspect(p.get("data") is Some(Data(_)), content="true")
}

///|
test "plist: an empty array and an empty dictionary decode to empty values" {
  // Apple writes `<array/>` as a zero-length SEQUENCE. It must produce an empty
  // Array rather than being rejected or treated as a string.
  let b = wrapped(
    dict([
      entry("arr", der(0x30, Bytes::from_array([]))),
      entry("dic", der(0xB0, Bytes::from_array([]))),
    ]),
  )
  let p = decode_der_plist(b)
  match p.get("arr") {
    Some(Array(items)) => inspect(items.length(), content="0")
    _ => fail("expected an empty array")
  }
  match p.get("dic") {
    Some(Dict(kv)) => inspect(kv.length(), content="0")
    _ => fail("expected an empty dictionary")
  }
}

///|
test "plist: integers sign-extend from their encoded width" {
  // DER writes the shortest form, so -5 is one byte 0xfb: a parser that
  // zero-extended would report 251.
  let b = wrapped(
    dict([
      entry("neg1", der(0x02, Bytes::from_array([b'\xfb']))),
      // -300 needs two bytes: 0xfed4.
      entry("neg2", der(0x02, Bytes::from_array([b'\xfe', b'\xd4']))),
      // 70000 is positive but sets the top bit of its leading byte, so it is
      // written as 00 01 11 70 and must not be sign-extended.
      entry(
        "big",
        der(0x02, Bytes::from_array([b'\x00', b'\x01', b'\x11', b'\x70'])),
      ),
    ]),
  )
  let p = decode_der_plist(b)
  inspect(p.get("neg1") is Some(Int(-5)), content="true")
  inspect(p.get("neg2") is Some(Int(-300)), content="true")
  inspect(p.get("big") is Some(Int(70000)), content="true")
}

///|
test "plist: nested arrays of dictionaries decode through every level" {
  let inner = dict([entry("z", der(0x0C, ascii("w")))])
  let arr = der(0x30, inner)
  let b = wrapped(dict([entry("a", arr)]))
  let p = decode_der_plist(b)
  inspect(p.get("a") is Some(Array([Dict([("z", Str("w"))])])), content="true")
}

///|
test "plist: a bare value without the version wrapper is accepted" {
  // Not every producer wraps the plist in tag 0x70. A bare dictionary must
  // decode rather than being reported as an unsupported tag.
  let b = dict([entry("k", der(0x0C, ascii("v")))])
  let p = decode_der_plist(b)
  inspect(p.get("k") is Some(Str("v")), content="true")
}

///|
test "plist: a wrapper that does not hold exactly two elements is rejected" {
  // Apple's wrapper is a version and a value. One child, or three, means this
  // is not the structure the decoder thinks it is.
  let b = der(0x70, der(0x0C, ascii("only")))
  try {
    ignore(decode_der_plist(b))
    fail("expected a rejection")
  } catch {
    Inconsistent(what~, ..) => inspect(what, content="DER plist")
    e => fail("unexpected error: \{e}")
  }
}

///|
test "plist: a boolean whose content is not one byte is rejected" {
  let b = wrapped(der(0x01, Bytes::from_array([b'\x01', b'\x01'])))
  try {
    ignore(decode_der_plist(b))
    fail("expected a rejection")
  } catch {
    BadValue(field~, ..) => inspect(field, content="DER boolean length")
    e => fail("unexpected error: \{e}")
  }
}

///|
test "plist: an integer wider than 64 bits is rejected, not truncated" {
  let nine = Bytes::from_array([
    b'\x01', b'\x02', b'\x03', b'\x04', b'\x05', b'\x06', b'\x07', b'\x08', b'\x09',
  ])
  let b = wrapped(der(0x02, nine))
  try {
    ignore(decode_der_plist(b))
    fail("expected a rejection")
  } catch {
    LimitExceeded(what~, ..) => inspect(what, content="DER integer width")
    e => fail("unexpected error: \{e}")
  }
}

///|
test "plist: an unknown value tag is reported rather than guessed at" {
  // Tag 0x05 is NULL in ASN.1 and never appears in a plist. Decoding it as
  // anything would invent a value the file does not contain.
  let b = wrapped(der(0x05, Bytes::from_array([])))
  try {
    ignore(decode_der_plist(b))
    fail("expected a rejection")
  } catch {
    Unsupported(what~) =>
      inspect(what.has_prefix("DER plist value tag"), content="true")
    e => fail("unexpected error: \{e}")
  }
}

///|
test "plist: a dictionary entry that is not a SEQUENCE is rejected" {
  // The members of Apple's dictionary are SEQUENCEs. A bare string where one
  // belongs means the structure is not a dictionary.
  let b = wrapped(der(0xB0, der(0x0C, ascii("loose"))))
  try {
    ignore(decode_der_plist(b))
    fail("expected a rejection")
  } catch {
    BadValue(field~, ..) => inspect(field, content="DER dict entry tag")
    e => fail("unexpected error: \{e}")
  }
}

///|
test "plist: a dictionary entry with one member is rejected" {
  let b = wrapped(der(0xB0, der(0x30, der(0x0C, ascii("key-only")))))
  try {
    ignore(decode_der_plist(b))
    fail("expected a rejection")
  } catch {
    Inconsistent(what~, ..) => inspect(what, content="DER dict entry")
    e => fail("unexpected error: \{e}")
  }
}

///|
test "plist: a dictionary key that is not a string is rejected" {
  // A key must be a UTF8String; an INTEGER there would otherwise be decoded
  // into a key of NUL bytes.
  let pair = der(
    0x30,
    cat([der(0x02, Bytes::from_array([b'\x01'])), der(0x0C, ascii("v"))]),
  )
  let b = wrapped(der(0xB0, pair))
  try {
    ignore(decode_der_plist(b))
    fail("expected a rejection")
  } catch {
    BadValue(field~, ..) => inspect(field, content="DER dict key tag")
    e => fail("unexpected error: \{e}")
  }
}

///|
test "plist: nesting deeper than the limit is rejected" {
  // 100 nested arrays: the decoder must stop at its own bound rather than
  // recursing until the stack gives out.
  let mut v = der(0x0C, ascii("x"))
  for _ in 0..<100 {
    v = der(0x30, v)
  }
  try {
    ignore(decode_der_plist(wrapped(v)))
    fail("expected a rejection")
  } catch {
    LimitExceeded(what~, ..) => inspect(what, content="DER plist nesting")
    e => fail("unexpected error: \{e}")
  }
}

///|
test "plist: an invalid UTF-8 string is rejected rather than replaced" {
  // 0xff is never valid in UTF-8. Silently substituting U+FFFD would lose the
  // fact that the payload is corrupt.
  let b = wrapped(der(0x0C, Bytes::from_array([b'\xff'])))
  try {
    ignore(decode_der_plist(b))
    fail("expected a rejection")
  } catch {
    BadName(..) => ()
    e => fail("unexpected error: \{e}")
  }
}

///|
test "plist: lookup on a non-dictionary is None, not an error" {
  inspect(Str("x").get("k") is None, content="true")
  inspect(Int(1).get("k") is None, content="true")
}

///|
test "plist: to_json renders each variant as the matching JSON type" {
  let p = Dict([
    ("b", Bool(true)),
    ("i", Int(-7)),
    ("s", Str("text")),
    ("d", Data(Bytes::from_array([b'\x00', b'\xab']))),
    ("a", Array([Int(1), Str("two")])),
    ("n", Dict([("inner", Bool(false))])),
  ])
  let text = p.to_json().stringify()
  // A round trip through the JSON parser proves the output is well formed;
  // comparing substrings proves each variant landed in the right JSON type.
  let parsed = Ok(@json.parse(text)) catch { e => Err(e) }
  match parsed {
    Ok(_) => ()
    Err(e) => fail("output is not valid JSON: \{e.to_string()}")
  }
  inspect(text.contains("\"b\":true"), content="true")
  inspect(text.contains("\"i\":-7"), content="true")
  inspect(text.contains("\"s\":\"text\""), content="true")
  // Data renders as hex, not as an array of numbers.
  inspect(text.contains("\"d\":\"00ab\""), content="true")
  inspect(text.contains("\"a\":[1,\"two\"]"), content="true")
  inspect(text.contains("\"n\":{\"inner\":false}"), content="true")
}

///|
test "plist: to_json renders an empty container as an empty JSON value" {
  inspect(Array([]).to_json().stringify(), content="[]")
  inspect(Dict([]).to_json().stringify(), content="{}")
}
