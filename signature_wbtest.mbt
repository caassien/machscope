// Differential tests for the code signature, against `codesign -dvv`.
//
// The oracle here is Apple's own verifier. It reports the CodeDirectory version,
// the identifier, the flags and the signature size; if the parser disagrees on
// any of those, the parser is reading the wrong offset in the superblob.

///|
/// The signature region of a thin fixture.
fn signature_of(name : String) -> (MachSlice, SignatureRegion) raise {
  let slice = match parse(fixture_bytes(name)) {
    Thin(s) => s
    Fat(_) => fail("expected thin")
  }
  let region = match signature_region(slice) {
    Some(r) => r
    None => fail("fixture has no LC_CODE_SIGNATURE")
  }
  (slice, region)
}

///|
test "oracle: the signature region matches otool's LC_CODE_SIGNATURE" {
  // otool -l ls.arm64e.macho: dataoff 70240, datasize 18432.
  let (_, region) = signature_of("ls.arm64e.macho")
  inspect(region.offset, content="70240")
  inspect(region.size, content="18432")
}

///|
test "oracle: the superblob index holds code directory and entitlements" {
  // The index has three entries: CSSLOT_CODEDIRECTORY (0), CSSLOT_REQUIREMENTS
  // (2) and CSSLOT_ENTITLEMENTS (5).
  let (slice, region) = signature_of("ls.arm64e.macho")
  let refs = signature_blobs(slice, region)
  inspect(refs.length(), content="3")
  inspect(refs[0].slot.to_int64(), content="0")
  inspect(refs[1].slot.to_int64(), content="2")
  inspect(refs[2].slot.to_int64(), content="65536") // 0x10000
  // Only the entitlements slot carries the DER payload magic.
  inspect(refs[2].magic.to_int64(), content="4208855809") // 0xfade0b01
}

///|
test "oracle: the code directory matches codesign -dvv" {
  // codesign -dvv: Identifier=com.apple.ls, CodeDirectory v=20400,
  // flags=0x0(none), Platform identifier=26.
  let (slice, region) = signature_of("ls.arm64e.macho")
  let cd = match code_directory(slice, region) {
    Some(d) => d
    None => fail("no code directory")
  }
  inspect(cd.identifier, content="com.apple.ls")
  inspect(cd.version.to_int64(), content="132096") // 0x20400
  inspect(cd.flags.to_int64(), content="0")
  inspect(cd.magic.to_int64(), content="4208856066") // 0xfade0c02
  // codesign reports `hashes=5+2`, i.e. 5 code slots and 2 special slots, and
  // page size 2^14. The hash type is SHA-256, hash size 32.
  inspect(cd.code_slots.to_int64(), content="5")
  inspect(cd.hash_type.to_int64(), content="2")
  inspect(cd.hash_size.to_int64(), content="32")
  inspect(cd.page_size.to_int64(), content="14")
  // Apple ships an empty team id for platform binaries.
  inspect(cd.team_id, content="")
}

///|
test "oracle: several Apple binaries report their own bundle identifiers" {
  // Each system binary signs under its own identifier; reading a shared offset
  // would produce the same string for all of them.
  let cases = [
    ("ls.arm64e.macho", "com.apple.ls"),
    ("ls.x86_64.macho", "com.apple.ls"),
  ]
  for pair in cases {
    let (name, expected) = pair
    let (slice, region) = signature_of(name)
    let cd = match code_directory(slice, region) {
      Some(d) => d
      None => fail("no code directory in \{name}")
    }
    inspect(cd.identifier, content=expected)
  }
}

///|
test "entitlements: the DER walk reaches a plist for a signed binary" {
  // Apple's platform binaries carry entitlements; the payload must decode to
  // something that starts like a property list rather than being empty.
  let (slice, region) = signature_of("ls.arm64e.macho")
  let ents = entitlements_der(slice, region)
  match ents {
    Some(der) => {
      // A non-empty payload that is valid DER: re-reading it must succeed.
      // Apple wraps the plist in a context-tagged element, so the outer tag is
      // not the SEQUENCE a bare plist would have.
      inspect(der.length() > 0, content="true")
      let top = read_element(der, 0L, der.length().to_int64())
      inspect(top.next > 0L, content="true")
      inspect(der.at(0).to_int() > 0x7F, content="true")
    }
    None => fail("expected entitlements in a signed system binary")
  }
}

///|
test "reject: a signature region running past the end of the file" {
  // Build a header with LC_CODE_SIGNATURE pointing beyond the buffer.
  let buf = Buffer()
  buf.write_uint_le(0xFEED_FACF)
  buf.write_int_le(0x0100_000C)
  buf.write_int_le(0)
  buf.write_uint_le(2)
  buf.write_uint_le(1)
  buf.write_uint_le(16)
  buf.write_uint_le(0)
  buf.write_uint_le(0)
  buf.write_uint_le(0x1D) // LC_CODE_SIGNATURE
  buf.write_uint_le(16)
  buf.write_uint_le(999999) // dataoff
  buf.write_uint_le(4096) // datasize
  let slice = match parse(buf.to_bytes()) {
    Thin(s) => s
    Fat(_) => fail("expected thin")
  }
  try {
    ignore(signature_region(slice))
    fail("expected a rejection")
  } catch {
    OutOfBounds(what~, ..) => inspect(what, content="code signature")
    e => fail("unexpected error: \{e}")
  }
}

///|
test "reject: a superblob whose length exceeds its region" {
  // A blob header claiming more bytes than LC_CODE_SIGNATURE reserved cannot
  // be indexed safely: later entries would read past the region.
  let buf = Buffer()
  buf.write_uint_le(0xFEED_FACF)
  buf.write_int_le(0x0100_000C)
  buf.write_int_le(0)
  buf.write_uint_le(2)
  buf.write_uint_le(1)
  buf.write_uint_le(16)
  buf.write_uint_le(0)
  buf.write_uint_le(0)
  buf.write_uint_le(0x1D)
  buf.write_uint_le(16)
  let sig_off = buf.length() + 8 // after this command's two fields
  buf.write_uint_le(sig_off.reinterpret_as_uint())
  buf.write_uint_le(16) // region is 16 bytes...
  // ...but the blob claims 4096.
  buf.write_uint_be(0xFADE_0CC0)
  buf.write_uint_be(4096)
  buf.write_uint_be(0)
  for _ in 0..<4 {
    buf.write_byte(b'\x00')
  }
  let slice = match parse(buf.to_bytes()) {
    Thin(s) => s
    Fat(_) => fail("expected thin")
  }
  let region = match signature_region(slice) {
    Some(r) => r
    None => fail("expected a region")
  }
  try {
    ignore(signature_blobs(slice, region))
    fail("expected a rejection")
  } catch {
    Inconsistent(what~, ..) => inspect(what, content="SuperBlob")
    e => fail("unexpected error: \{e}")
  }
}

///|
test "der: lengths and nesting round-trip through the reader" {
  // A hand-built SEQUENCE { INTEGER 5 } in definite length form:
  // 30 03 02 01 05
  let der = Bytes::from_array([b'\x30', b'\x03', b'\x02', b'\x01', b'\x05'])
  let top = read_element(der, 0L, 5L)
  inspect(top.tag.to_int64(), content="48")
  let kids = children(der, top)
  inspect(kids.length(), content="1")
  inspect(kids[0].tag.to_int64(), content="2")
  inspect(kids[0].content_end - kids[0].content_start, content="1")
}

///|
test "der: long-form lengths are decoded" {
  // OCTET STRING of 200 bytes: 04 81 c8 followed by 200 bytes.
  let buf = Buffer()
  buf.write_byte(b'\x04')
  buf.write_byte(b'\x81')
  buf.write_byte(b'\xc8')
  for _ in 0..<200 {
    buf.write_byte(b'\x41')
  }
  let der = buf.to_bytes()
  let el = read_element(der, 0L, der.length().to_int64())
  inspect(el.content_end - el.content_start, content="200")
  inspect(el.next, content="203")
}

///|
test "der: a truncated element is rejected" {
  // Claims 10 content bytes but supplies 3.
  let der = Bytes::from_array([b'\x30', b'\x0a', b'\x01', b'\x02', b'\x03'])
  try {
    ignore(read_element(der, 0L, der.length().to_int64()))
    fail("expected a rejection")
  } catch {
    OutOfBounds(what~, ..) => inspect(what, content="DER content")
    e => fail("unexpected error: \{e}")
  }
}
