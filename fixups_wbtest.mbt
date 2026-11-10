// Differential tests for chained fixups, against `dyld_info -fixups`.
//
// sample.bin has one fixup, a bind to libSystem/_printf, which `dyld_info`
// prints as `__DATA_CONST __got 0x100004000 bind libSystem/_printf`.
//
// `sample.bin` is plain arm64, so its one slot uses `DYLD_CHAINED_PTR_64_OFFSET`:
// a 36-bit target with a bind bit and a 12-bit stride, no pointer
// authentication. `sample.arm64e` is the same source built with `-arch arm64e`,
// and its slot is an authenticated bind, which is the shape the old `/bin/ls`
// fixture exercised.
//
// The old fixture had 113 fixups across two segments; the samples have one
// fixup in one segment, so the multi-segment chain-table shape is no longer
// exercised. Everything else those tests asserted — the authenticated pointer
// layout, the key and discriminator bits, and the stride unit — is still
// covered here against a real arm64e build.

///|
/// The chained fixups of a thin fixture.
fn fixups_of(name : String) -> ChainedFixups raise {
  let slice = match parse(fixture_bytes(name)) {
    Thin(s) => s
    Fat(_) => fail("expected thin")
  }
  match chained_fixups(slice) {
    Some(f) => f
    None => fail("fixture has no chained fixups")
  }
}

///|
test "oracle: the blob header matches otool's dataoff and datasize" {
  // otool -l sample.bin: LC_DYLD_CHAINED_FIXUPS dataoff 32768, datasize 96.
  let slice = match parse(fixture_bytes("sample.bin")) {
    Thin(s) => s
    Fat(_) => fail("expected thin")
  }
  let mut found = false
  for cmd in slice.commands {
    if cmd.cmd == LC_DYLD_CHAINED_FIXUPS {
      found = true
      let body = command_payload(slice, cmd)
      let (off, cur) = body.read_u32(Cursor::{
        pos: body.start,
        endian: Endian::Little,
      })
      inspect(off.to_int64(), content="32768")
      let (size, _) = body.read_u32(cur)
      inspect(size.to_int64(), content="96")
    }
  }
  inspect(found, content="true")
}

///|
test "oracle: sample.bin imports one symbol from libSystem" {
  // dyld_info -imports sample.bin: 0x0000 _printf (from libSystem).
  let f = fixups_of("sample.bin")
  inspect(f.imports.length(), content="1")
  inspect(f.imports[0].name, content="_printf")
  inspect(f.imports[0].library_ordinal.to_int64(), content="1")
  inspect(f.imports[0].weak, content="false")
  inspect(f.version.to_int64(), content="0")
}

///|
test "oracle: sample.bin has one fixup, a bind at 0x100004000" {
  let slice = match parse(fixture_bytes("sample.bin")) {
    Thin(s) => s
    Fat(_) => fail("expected thin")
  }
  let list = fixups(slice)
  inspect(list.length(), content="1")
  inspect(list[0].address, content="4294983680") // 0x100004000
  inspect(list[0].is_bind(), content="true")
  match list[0].symbol {
    Some(s) => inspect(s, content="_printf")
    None => fail("expected a symbol on a bind")
  }
}

///|
test "oracle: the sample's fixup sits in __got, as dyld_info reports" {
  // dyld_info names the segment and section: `__DATA_CONST __got`. The section
  // is the one dyld_info prints, not merely one that happens to overlap.
  let slice = match parse(fixture_bytes("sample.bin")) {
    Thin(s) => s
    Fat(_) => fail("expected thin")
  }
  let list = fixups(slice)
  let segs = segments(slice)
  // The address must fall inside the section dyld_info names.
  let got = match find_section(segs, "__DATA_CONST", "__got") {
    Some(s) => s
    None => fail("expected __DATA_CONST,__got")
  }
  if list[0].address < got.addr || list[0].address >= got.addr + got.size {
    fail("fixup address is not inside __got")
  }
  // And the slot address is exactly the section's first byte, which is where
  // dyld_info prints 0x100004000.
  inspect(got.addr, content=list[0].address.to_string())
}

///|
test "fixups: the chain table names __DATA_CONST and its page" {
  // The starts table has an entry for every segment but only the __got slot is
  // fixed up, so exactly one segment carries a chain. `dyld_info` attributes
  // the fixup to __DATA_CONST, which is the third segment in file order.
  //
  // The old fixture had chains in two segments (__DATA_CONST and __DATA) and
  // this test asserted both; the linker that produced our fixtures puts the
  // single bind in __got and therefore emits one chain table. The two-segment
  // shape is no longer exercised.
  let f = fixups_of("sample.bin")
  inspect(f.segments.length(), content="1")
  inspect(f.segments[0].segment_index, content="2")
  // `page_size` is a byte count here: 0x4000 for a 16 KiB page.
  inspect(f.segments[0].page_size.to_int64(), content="16384")
  // DYLD_CHAINED_PTR_64_OFFSET: no authentication, target is a file offset.
  inspect(f.segments[0].pointer_format.to_int64(), content="6")
  // The bind sits at the start of the page, so the single page start is 0.
  inspect(f.segments[0].page_starts.length(), content="1")
  inspect(f.segments[0].page_starts[0].to_int64(), content="0")
}

///|
test "arm64: a plain fixup carries no authentication metadata" {
  // `dyld_info -fixups sample.bin` prints no `auth` column, and the slots are
  // `DYLD_CHAINED_PTR_64_OFFSET`, whose bind form has no key or diversity
  // field. This test replaces the old arm64e assertions: it pins down that the
  // decoded fixups really are unauthenticated, which is the property the
  // pointer format implies, rather than asserting values no fixture has.
  let slice = match parse(fixture_bytes("sample.bin")) {
    Thin(s) => s
    Fat(_) => fail("expected thin")
  }
  for f in fixups(slice) {
    inspect(f.has_discriminator, content="false")
    inspect(f.key.to_int64(), content="0")
    inspect(f.diversity.to_int64(), content="0")
  }
}

///|
test "oracle: an arm64e auth-bind carries its signing key and diversity" {
  // `sample.arm64e` is the same `sample.c` built with `-arch arm64e`. dyld_info
  // reports its one import as
  //   __DATA_CONST __auth_got 0x100004000 auth-bind libSystem/_printf (div=0x0000 ad=1 key=IA)
  // so the slot decodes as an authenticated bind. `key=IA` is
  // `DYLD_CHAINED_PTR_ARM64E_KEY_IA`, which is 0 in the two-bit key field
  // (IA, IB, DA, DB are 0 through 3 — dyld_info's mnemonics are not the raw
  // number), `div=0x0000` is a diversity of 0, and `ad=1` sets the address
  // discriminator bit.
  let slice = match parse(fixture_bytes("sample.arm64e")) {
    Thin(s) => s
    Fat(_) => fail("expected thin")
  }
  let found : Array[Fixup] = fixups(slice)
  inspect(found.length(), content="1")
  let f = found[0]
  inspect(f.address, content="4294983680") // 0x100004000
  inspect(f.is_bind(), content="true")
  match f.symbol {
    Some(name) => inspect(name, content="_printf")
    None => fail("expected a bound symbol")
  }
  inspect(f.key.to_int64(), content="0") // key IA
  inspect(f.diversity.to_int64(), content="0")
  inspect(f.has_discriminator, content="true") // ad=1
  // The chain table for this binary declares pointer format 12,
  // `DYLD_CHAINED_PTR_ARM64E_USERLAND24`, which widens the bind ordinal to 24
  // bits. Asserting it here is what pins down that the format is decoded
  // rather than rejected as unsupported.
  let index = match chained_fixups(slice) {
    Some(c) => c
    None => fail("expected a fixup index")
  }
  inspect(index.segments[0].pointer_format.to_int64(), content="12")
}

///|
test "fixups: every address lands inside a mapped segment" {
  // A chain walk that mis-computes the page base would produce addresses in
  // no segment at all; this catches that without needing a per-address oracle.
  let slice = match parse(fixture_bytes("sample.bin")) {
    Thin(s) => s
    Fat(_) => fail("expected thin")
  }
  let segs = segments(slice)
  for f in fixups(slice) {
    let mut inside = false
    for seg in segs {
      if seg.contains_address(f.address) && seg.file_size > 0L {
        inside = true
      }
    }
    if !inside {
      fail("fixup at 0x\{hex(f.address)} is outside every file-backed segment")
    }
  }
}

///|
test "reject: an import table running past the fixup blob" {
  // A blob claiming more imports than it can hold must be rejected during
  // indexing, not when the chain walk tries to name a symbol.
  let slice = match parse(fixture_bytes("sample.bin")) {
    Thin(s) => s
    Fat(_) => fail("expected thin")
  }
  let b = slice.bounds
  let e = Endian::Little
  // imports_count sits 16 bytes into the header; overwrite a copy of the
  // header with a count that cannot fit.
  let start = 32768L
  let cur = Cursor::{ pos: start, endian: e, }
  let (_, c) = b.read_u32(cur) // version
  let (starts_off, c) = b.read_u32(c)
  let (imports_off, c) = b.read_u32(c)
  let (symbols_off, c) = b.read_u32(c)
  let _ = c
  // Re-read the real header fields to build a bogus table by hand.
  let real_imports = start + imports_off.to_int64()
  let symbols_at = start + symbols_off.to_int64()
  let outcome = Ok(
    read_imports(
      b,
      real_imports,
      100000U,
      CHAINED_IMPORT_FORMAT,
      symbols_at,
      start + 96L,
    ),
  ) catch {
    err => Err(err)
  }
  let _ = starts_off
  match outcome {
    Ok(_) => fail("expected a rejection")
    Err(_) => ()
  }
}
