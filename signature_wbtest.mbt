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
  // otool -l sample.bin: LC_CODE_SIGNATURE dataoff 33392, datasize 416.
  let (_, region) = signature_of("sample.bin")
  inspect(region.offset, content="33392")
  inspect(region.size, content="416")
}

///|
test "oracle: the superblob index holds only the code directory" {
  // `codesign -dvvv sample.bin` reports `flags=0x20002(adhoc,linker-signed)`
  // and `Internal requirements=none`, and the index has exactly one entry:
  // CSSLOT_CODEDIRECTORY (0). An ad-hoc signature from the linker carries no
  // requirements blob, no CMS blob and no entitlements.
  let (slice, region) = signature_of("sample.bin")
  let refs = signature_blobs(slice, region)
  inspect(refs.length(), content="1")
  inspect(refs[0].slot.to_int64(), content="0")
  inspect(refs[0].magic.to_int64(), content="4208856066") // 0xfade0c02
  inspect(refs[0].length, content="389")
}

///|
test "oracle: the code directory matches codesign -dvv" {
  // codesign -dvvv sample.bin: Identifier=sample.arm64, CodeDirectory v=20400,
  // flags=0x20002(adhoc,linker-signed), hashes=9+0, Hash type=sha256 size=32,
  // TeamIdentifier=not set.
  let (slice, region) = signature_of("sample.bin")
  let cd = match code_directory(slice, region) {
    Some(d) => d
    None => fail("no code directory")
  }
  inspect(cd.identifier, content="sample.arm64")
  inspect(cd.version.to_int64(), content="132096") // 0x20400
  inspect(cd.flags.to_int64(), content="131074") // 0x20002
  inspect(cd.magic.to_int64(), content="4208856066") // 0xfade0c02
  // codesign reports `hashes=9+0`, i.e. 9 code slots and no special slots.
  // The hash type is SHA-256, hash size 32, and the page size is 2^12 (4 KiB),
  // which is what clang's linker writes for these small images.
  inspect(cd.code_slots.to_int64(), content="9")
  inspect(cd.hash_type.to_int64(), content="2")
  inspect(cd.hash_size.to_int64(), content="32")
  inspect(cd.page_size.to_int64(), content="12")
  // `TeamIdentifier=not set`: an ad-hoc signature has no team id.
  inspect(cd.team_id, content="")
}

///|
test "oracle: only the arm64 slice of the fat file is signed" {
  // The linker applies its ad-hoc signature to arm64 images only, so the
  // x86_64 image `make_fixtures.sh` produces carries no LC_CODE_SIGNATURE at
  // all: `codesign -dvvv` on that slice says `code object is not signed at
  // all`, and the arm64 slice reports `Identifier=sample.arm64`. Reading a
  // shared offset would report the arm64 directory for both, so the two
  // answers are asserted separately.
  let slices = match parse(fixture_bytes("sample.fat")) {
    Fat(s) => s
    Thin(_) => fail("expected fat")
  }
  inspect(signature_region(slices[0].image) is None, content="true")
  let region = match signature_region(slices[1].image) {
    Some(r) => r
    None => fail("expected a signature on the arm64 slice")
  }
  let cd = match code_directory(slices[1].image, region) {
    Some(d) => d
    None => fail("no code directory in the arm64 slice")
  }
  inspect(cd.identifier, content="sample.arm64")
}

///|
test "entitlements: our own binary genuinely carries none" {
  // `codesign -d --entitlements :- sample.bin` prints nothing: an ad-hoc
  // linker-signed image has neither slot 5 nor slot 7. The previous version of
  // this file asserted the opposite on an Apple binary and passed, because it
  // was reading a signature blob rather than an entitlements blob.
  let (slice, region) = signature_of("sample.bin")
  let refs = signature_blobs(slice, region)
  inspect(refs.length(), content="1")
  inspect(entitlements(slice, region) is None, content="true")
}

///|
test "entitlements: the DER payload decodes to the plist codesign reports" {
  // entitlements.der was extracted from slot 7 of a binary signed with
  // `codesign --entitlements entitled.plist`. `codesign -d --entitlements -`
  // on that binary prints exactly the dictionary asserted here.
  let plist = decode_der_plist(fixture_bytes("entitlements.der"))
  inspect(
    plist.get("com.apple.security.get-task-allow") is Some(Bool(true)),
    content="true",
  )
  inspect(plist.get("com.example.counter") is Some(Int(42)), content="true")
  inspect(
    plist.get("com.example.label") is Some(Str("machscope")),
    content="true",
  )
  inspect(
    plist.get("com.example.list") is Some(Array([Str("a"), Int(7)])),
    content="true",
  )
  inspect(
    plist.get("com.example.nested") is Some(Dict([("inner", Str("deep"))])),
    content="true",
  )
}

///|
test "entitlements: the DER plist has a version of 1" {
  // Apple's wrapper is an application-tagged element holding an INTEGER
  // version and then the dictionary. Reading the version as the value would
  // yield `Int(1)` instead of a dictionary.
  let plist = decode_der_plist(fixture_bytes("entitlements.der"))
  inspect(plist is Dict(_), content="true")
}

///|
test "entitlements: the XML payload is valid UTF-8 plist text" {
  // Slot 5 holds the same dictionary as XML. It must decode as text and start
  // with an XML declaration, which is what distinguishes it from the DER slot.
  let text = @utf8.decode(fixture_bytes("entitlements.xml")) catch {
    _ => fail("XML entitlements are not valid UTF-8")
  }
  inspect(text.has_prefix("<?xml version=\"1.0\""), content="true")
  inspect(text.contains("<key>com.example.counter</key>"), content="true")
}

///|
test "entitlements: a DER plist with a bad version is rejected" {
  // The wrapper's version is INTEGER 1. Bumping it to 2 must fail rather than
  // silently parsing a structure whose meaning has changed.
  let bytes = fixture_bytes("entitlements.der")
  let buf = Buffer()
  for i in 0..<bytes.length() {
    buf.write_byte(bytes.at(i))
  }
  let mutated = buf.to_bytes()
  // The version integer is the third byte of the encoded wrapper: 70 81 ab 02 01 01 ...
  let patched = Bytes::from_array([
    b'\x70', b'\x81', b'\xab', b'\x02', b'\x01', b'\x02',
  ])
  let out = Buffer()
  for i in 0..<patched.length() {
    out.write_byte(patched.at(i))
  }
  for i in 6..<mutated.length() {
    out.write_byte(mutated.at(i))
  }
  try {
    ignore(decode_der_plist(out.to_bytes()))
    fail("expected a rejection")
  } catch {
    BadValue(field~, ..) => inspect(field, content="DER plist version")
    e => fail("unexpected error: \{e}")
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

///|
/// Builds a minimal Mach-O whose `LC_CODE_SIGNATURE` points at `superblob`.
///
/// The superblob tests need to control which slot holds which blob, and no
/// real signed binary can be committed for that: `codesign` stamps the current
/// time into the CMS blob and into the CodeDirectory, so two signings of the
/// same input differ. A constructed superblob is exact and reproducible.
fn image_signing(superblob : Bytes) -> MachSlice raise {
  let header_size = 32
  let cmd_size = 16
  let sig_off = header_size + cmd_size
  let buf = Buffer()
  buf.write_uint_le(0xFEED_FACF) // MH_MAGIC_64
  buf.write_int_le(0x0100_000C) // CPU_TYPE_ARM64
  buf.write_int_le(0)
  buf.write_uint_le(2) // MH_EXECUTE
  buf.write_uint_le(1U) // ncmds
  buf.write_uint_le(cmd_size.reinterpret_as_uint()) // sizeofcmds
  buf.write_uint_le(0) // flags
  buf.write_uint_le(0) // reserved
  buf.write_uint_le(0x1DU) // LC_CODE_SIGNATURE
  buf.write_uint_le(cmd_size.reinterpret_as_uint())
  buf.write_uint_le(sig_off.reinterpret_as_uint())
  buf.write_uint_le(superblob.length().reinterpret_as_uint())
  for i in 0..<superblob.length() {
    buf.write_byte(superblob.at(i))
  }
  match parse(buf.to_bytes()) {
    Thin(s) => s
    Fat(_) => fail("expected thin")
  }
}

///|
/// Assembles a superblob from `(slot, magic, payload)` triples, big-endian as
/// the format requires.
fn superblob_of(entries : Array[(UInt32, UInt32, Bytes)]) -> Bytes {
  let index_size = 12 + entries.length() * 8
  let buf = Buffer()
  buf.write_uint_be(0xFADE_0CC0)
  let mut total = index_size
  for e in entries {
    total = total + 8 + e.2.length()
  }
  buf.write_uint_be(total.reinterpret_as_uint())
  buf.write_uint_be(entries.length().reinterpret_as_uint())
  let mut at = index_size
  for e in entries {
    buf.write_uint_be(e.0)
    buf.write_uint_be(at.reinterpret_as_uint())
    at = at + 8 + e.2.length()
  }
  for e in entries {
    buf.write_uint_be(e.1)
    buf.write_uint_be((8 + e.2.length()).reinterpret_as_uint())
    for i in 0..<e.2.length() {
      buf.write_byte(e.2.at(i))
    }
  }
  buf.to_bytes()
}

///|
test "entitlements: the DER slot is 7 and the XML slot is 5, not the reverse" {
  // This is the distinction the first review of this project rejected the
  // submission over, and until this test existed nothing could catch getting
  // the two numbers backwards: the payload fixtures assert only that a blob
  // decodes, and both slots' blobs decode the same way.
  //
  // The superblob below carries the same payload in slots 5 and 7 with their
  // distinct magics. Only slot 7 may be read as DER.
  let der_payload = fixture_bytes("entitlements.der")
  let xml_payload = fixture_bytes("entitlements.xml")
  let sb = superblob_of([
    (0U, 0xFADE_0C02U, Bytes::make(8, b'\x00')), // a CodeDirectory stand-in
    (5U, 0xFADE_7171U, xml_payload),
    (7U, 0xFADE_7172U, der_payload),
    (0x1_0000U, 0xFADE_0B01U, Bytes::make(8, b'\x00')),
  ])
  let slice = image_signing(sb)
  let region = match signature_region(slice) {
    Some(r) => r
    None => fail("expected a signature region")
  }
  let refs = signature_blobs(slice, region)
  inspect(refs.length(), content="4")
  // The index lists slots in order; asserting each is what pins the constants.
  inspect(refs[0].slot.to_int64(), content="0")
  inspect(refs[1].slot.to_int64(), content="5")
  inspect(refs[1].magic.to_int64(), content="4208882033") // 0xfade7171
  inspect(refs[2].slot.to_int64(), content="7")
  inspect(refs[2].magic.to_int64(), content="4208882034") // 0xfade7172
  inspect(refs[3].slot.to_int64(), content="65536")
  // The decoder prefers slot 7 and returns the DER form, which is a dictionary.
  match entitlements(slice, region) {
    Some(e) => {
      inspect(e.magic.to_int64(), content="4208882034") // 0xfade7172
      inspect(e.value is Dict(_), content="true")
      inspect(
        e.value.get("com.example.counter") is Some(Int(42)),
        content="true",
      )
    }
    None => fail("expected entitlements")
  }
}

///|
test "entitlements: with only slot 5 present the XML payload comes back" {
  // The other half of the branch: an image carrying only the XML form must
  // still yield entitlements, as text rather than a decoded dictionary.
  let xml_payload = fixture_bytes("entitlements.xml")
  let sb = superblob_of([
    (0U, 0xFADE_0C02U, Bytes::make(8, b'\x00')),
    (5U, 0xFADE_7171U, xml_payload),
  ])
  let slice = image_signing(sb)
  let region = match signature_region(slice) {
    Some(r) => r
    None => fail("expected a signature region")
  }
  match entitlements(slice, region) {
    Some(e) => {
      inspect(e.magic.to_int64(), content="4208882033") // 0xfade7171
      match e.value {
        Str(text) =>
          inspect(text.has_prefix("<?xml version=\"1.0\""), content="true")
        _ => fail("expected the XML form as a string")
      }
    }
    None => fail("expected entitlements from slot 5 alone")
  }
}

///|
test "entitlements: the CMS slot alone yields none" {
  // Slot 0x10000 holds the CMS signature over the CodeDirectory. Walking it for
  // an OCTET STRING and calling the result "entitlements" is the bug that got
  // the first submission rejected, so an image with only that slot must return
  // None. `/bin/ls` is the real-world case and is asserted separately above;
  // this is the constructed one.
  let sb = superblob_of([
    (0U, 0xFADE_0C02U, Bytes::make(8, b'\x00')),
    (0x1_0000U, 0xFADE_0B01U, Bytes::make(64, b'\x7f')),
  ])
  let slice = image_signing(sb)
  let region = match signature_region(slice) {
    Some(r) => r
    None => fail("expected a signature region")
  }
  inspect(entitlements(slice, region) is None, content="true")
}

///|
test "entitlements: a payload whose magic contradicts its slot is ignored" {
  // The slot number and the magic must both say entitlements. A blob whose
  // magic says entitlements but which sits in the CMS slot is not one, and
  // neither is one in slot 5 whose magic belongs to a CodeDirectory.
  let der_payload = fixture_bytes("entitlements.der")
  let sb = superblob_of([
    (5U, 0xFADE_0C02U, der_payload), // wrong magic for slot 5
    (7U, 0xFADE_7171U, der_payload), // wrong magic for slot 7
  ])
  let slice = image_signing(sb)
  let region = match signature_region(slice) {
    Some(r) => r
    None => fail("expected a signature region")
  }
  inspect(entitlements(slice, region) is None, content="true")
}
