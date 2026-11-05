// Differential tests for chained fixups, against `dyld_info -fixups`.
//
// sample.bin has one fixup, a bind to libSystem/_printf, which `dyld_info`
// prints as `__DATA_CONST __got 0x100004000 bind libSystem/_printf`.
// ls.arm64e has 114, all auth-binds through the arm64e pointer format.

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
  // otool -l sample.bin: dataoff 32768, datasize 96.
  let slice = match parse(fixture_bytes("sample.bin")) {
    Thin(s) => s
    Fat(_) => fail("expected thin")
  }
  let mut found = false
  for cmd in slice.commands {
    if cmd.cmd == LC_DYLD_CHAINED_FIXUPS {
      found = true
      let body = command_payload(slice, cmd)
      let (off, _) = body.read_u32(Cursor::{
        pos: body.start,
        endian: Endian::Little,
      })
      inspect(off.to_int64(), content="32768")
    }
  }
  inspect(found, content="true")
}

///|
test "oracle: sample.bin imports one symbol from libSystem" {
  // dyld_info -imports: 0x0000 _printf (from libSystem).
  let f = fixups_of("sample.bin")
  inspect(f.imports.length(), content="1")
  inspect(f.imports[0].name, content="_printf")
  inspect(f.imports[0].library_ordinal.to_int64(), content="1")
  inspect(f.imports[0].weak, content="false")
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
}

///|
test "oracle: ls.arm64e names its imports even though its chains are undecoded" {
  // `dyld_info -fixups ls.arm64e.macho | grep auth-bind | wc -l` is 114. The
  // import table itself is readable; only the chain walk is not, so the names
  // and library ordinals are still available.
  let f = fixups_of("ls.arm64e.macho")
  inspect(f.imports.length(), content="90")
  inspect(f.imports[0].name, content="_humanize_number")
  inspect(f.imports[0].library_ordinal.to_int64(), content="1")
  inspect(f.segments.length(), content="2")
}

///|
test "arm64e chains are reported as unsupported rather than guessed at" {
  // Returning one fixup where there are 114 would be worse than an error: a
  // caller cannot tell a short answer from a wrong one.
  let slice = match parse(fixture_bytes("ls.arm64e.macho")) {
    Thin(s) => s
    Fat(_) => fail("expected thin")
  }
  let outcome = Ok(fixups(slice)) catch { e => Err(e) }
  match outcome {
    Ok(_) => fail("expected an Unsupported error for arm64e chains")
    Err(_) => ()
  }
}

///|
test "oracle: the segment chain table names __DATA_CONST and __DATA" {
  // dyld_info reports fixups in both segments; the starts table lists each.
  let f = fixups_of("ls.arm64e.macho")
  inspect(f.segments[0].segment_index, content="2")
  inspect(f.segments[1].segment_index, content="3")
  inspect(f.segments[0].page_starts.length(), content="1")
}

///|
test "oracle: every fixup address lands inside a mapped segment" {
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
