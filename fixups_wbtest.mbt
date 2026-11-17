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

///|
/// Encodes the four arm64e slot kinds from their fields, the inverse of what
/// `decode_slot` does.
fn arm64e_slot(
  auth : Bool,
  bind : Bool,
  ordinal : Int64,
  diversity : Int64,
  discriminator : Bool,
  key : Int64,
  next : Int64,
  target : Int64,
) -> Int64 {
  let mut v = 0L
  if auth {
    v = v | 0x8000_0000_0000_0000L
  }
  if bind {
    v = v | 0x4000_0000_0000_0000L
  }
  v = v | ((next & 0x7FFL) << 51)
  if bind {
    v = v | (ordinal & 0xFF_FFFFL)
    if auth {
      v = v | ((diversity & 0xFFFFL) << 32)
      if discriminator {
        v = v | (1L << 48)
      }
      v = v | ((key & 0x3L) << 49)
    }
  } else if auth {
    v = v | (target & 0xFFFF_FFFFL)
    v = v | ((diversity & 0xFFFFL) << 32)
    if discriminator {
      v = v | (1L << 48)
    }
    v = v | ((key & 0x3L) << 49)
  } else {
    v = v | (target & 0x0000_07FF_FFFF_FFFFL)
  }
  v
}

///|
test "slot: the plain 64-bit bind and rebase forms decode" {
  // dyld_chained_ptr_64_bind: ordinal:24 at bit 0, next:12, bind bit set.
  let bind = 0x8000_0040_0000_0007L // bind, next=0x40, ordinal=7
  inspect(
    decode_slot(bind, CHAINED_PTR_64) is Some(Bind(7L, 0, 0, false)),
    content="true",
  )
  // dyld_chained_ptr_64_rebase: target:36 at bit 0, bind bit clear.
  let rebase = 0x0000_0000_0000_0123L
  inspect(
    decode_slot(rebase, CHAINED_PTR_64) is Some(Rebase(0x123L, 0, 0, false)),
    content="true",
  )
  // high8 occupies bits 36..43. The target mask is 36 bits wide, so a slot
  // whose high8 is set must still report exactly the low 36 bits as the
  // target; a mask one nibble too wide would fold part of high8 into it.
  let with_high8 = (0xABL << 36) | 0x123L
  inspect(
    decode_slot(with_high8, CHAINED_PTR_64_OFFSET)
    is Some(Rebase(0x123L, 0, 0, false)),
    content="true",
  )
}

///|
test "slot: the arm64e authenticated bind carries key and diversity" {
  let raw = arm64e_slot(true, true, 5L, 0xBEEFL, true, 3L, 2L, 0L)
  let got = decode_slot(raw, CHAINED_PTR_ARM64E_USERLAND24)
  inspect(got is Some(Bind(5L, 3, 0xBEEF, true)), content="true")
}

///|
test "slot: the arm64e plain bind ignores the diversity field" {
  let raw = arm64e_slot(false, true, 9L, 0L, false, 0L, 0L, 0L)
  inspect(
    decode_slot(raw, CHAINED_PTR_ARM64E) is Some(Bind(9L, 0, 0, false)),
    content="true",
  )
}

///|
test "slot: the arm64e authenticated rebase keeps its 32-bit target" {
  let raw = arm64e_slot(true, false, 0L, 0x1234L, false, 1L, 0L, 0xDEAD_BEEFL)
  let got = decode_slot(raw, CHAINED_PTR_ARM64E_USERLAND)
  inspect(got is Some(Rebase(0xDEAD_BEEFL, 1, 0x1234, false)), content="true")
}

///|
test "slot: the arm64e plain rebase carries a 43-bit target" {
  // 43 bits is the widest target field of any of these formats; a mask that is
  // one bit short silently truncates every rebase by half the address space.
  let widest = 0x0000_07FF_FFFF_FFFFL
  let raw = arm64e_slot(false, false, 0L, 0L, false, 0L, 0L, widest)
  // `is Some(Rebase(widest, ..))` would bind a new variable rather than
  // compare, so match explicitly and check the field.
  match decode_slot(raw, CHAINED_PTR_ARM64E) {
    Some(Rebase(t, k, d, disc)) => {
      inspect(t, content=widest.to_string())
      inspect(k.to_int64(), content="0")
      inspect(d.to_int64(), content="0")
      inspect(disc, content="false")
    }
    _ => fail("expected a rebase")
  }
}

///|
test "slot: _USERLAND24 widens the ordinal but _USERLAND does not" {
  // The two differ only in the ordinal width. A 24-bit ordinal must survive in
  // one and be masked to 16 bits in the other.
  let raw = arm64e_slot(true, true, 0xFF_FFFFL, 0L, false, 0L, 0L, 0L)
  inspect(
    decode_slot(raw, CHAINED_PTR_ARM64E_USERLAND24)
    is Some(Bind(0xFF_FFFFL, 0, 0, false)),
    content="true",
  )
  inspect(
    decode_slot(raw, CHAINED_PTR_ARM64E_USERLAND)
    is Some(Bind(0xFFFFL, 0, 0, false)),
    content="true",
  )
}

///|
test "slot: an unknown pointer format is None rather than a guess" {
  // 0 is not a valid pointer format. Returning a plausible-looking slot for it
  // would report addresses nobody wrote.
  inspect(decode_slot(0L, 0U) is None, content="true")
  inspect(decode_slot(0xFFFFL, 99U) is None, content="true")
}

///|
test "stride: arm64e counts in 8-byte slots and the 64-bit formats in words" {
  // The same bit field means a different distance depending on the format.
  // Using the wrong unit walks into the middle of the next pointer.
  let raw = 3L << 51 // arm64e next field = 3
  inspect(slot_stride(raw, CHAINED_PTR_ARM64E), content="24")
  inspect(slot_stride(raw, CHAINED_PTR_ARM64E_USERLAND24), content="24")
  // For the 64-bit formats the low 12 bits are the stride, in 4-byte words.
  let raw64 = 3L
  inspect(slot_stride(raw64, CHAINED_PTR_64), content="12")
  inspect(slot_stride(raw64, CHAINED_PTR_64_OFFSET), content="12")
}

///|
test "imports: lookup by index returns None past the end" {
  let imports : Array[ChainedImport] = [
    ChainedImport::{
      name_offset: 0U,
      name: "a",
      library_ordinal: 1U,
      weak: false,
    },
  ]
  inspect(lookup_import(imports, 0L) is Some(_), content="true")
  inspect(lookup_import(imports, 1L) is None, content="true")
  inspect(lookup_import(imports, -1L) is None, content="true")
}
