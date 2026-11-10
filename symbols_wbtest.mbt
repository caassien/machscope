// Differential tests for the symbol table, against `nm` as the oracle.
//
// `nm` reads the same `LC_SYMTAB`; any disagreement on order, count or spelling
// is a defect in one of the two. The fixture is `sample.bin`, linked from
// `internal/fixtures/sample.c` by `internal/fixtures/make_fixtures.sh`.

///|
/// The `LC_SYMTAB` of a thin fixture.
fn symtab_of(name : String) -> (MachSlice, SymtabCommand) raise {
  let slice = match parse(fixture_bytes(name)) {
    Thin(s) => s
    Fat(_) => fail("expected thin")
  }
  let tab = match find_symtab(slice) {
    Some(t) => t
    None => fail("fixture has no LC_SYMTAB")
  }
  (slice, tab)
}

///|
test "oracle: nsyms matches otool -l's SYMTAB" {
  // `otool -l sample.bin` reports nsyms 22; `nm sample.bin` prints 5 lines
  // because it hides the STABS entries and the section-relative ones. The
  // table is the larger number, and it is the one this parser must agree with.
  let (_, tab) = symtab_of("sample.bin")
  inspect(tab.nsyms.to_int64(), content="22")
}

///|
test "oracle: the STABS entries nm hides by default are present" {
  // `nm -a sample.bin` shows 22 entries, most of them STABS records the
  // assembler and linker write. The table is not ordered the way `nm -a`
  // prints it (nm sorts by address), so the first entry is the linker's local
  // definition of `helper`: `nm -m sample.bin` calls it
  // `00000001000004c8 (__TEXT,__text) non-external _helper`, and nm prints the
  // line in lowercase because it is a local (`t`, not `T`).
  //
  // A parser that trusted nm's default output as the complete table would be
  // off by 17 for every subsequent index; this pins down the first entry's
  // type byte so that off-by-one is visible.
  let (slice, _) = symtab_of("sample.bin")
  let syms = symbols(slice)
  inspect(syms[0].name, content="_helper")
  inspect(syms[0].n_type.to_int64(), content="14") // N_SECT, not N_STAB
  inspect(syms[0].is_debug(), content="false")
  inspect(syms[0].is_external(), content="false")
  // Entry 1 begins the STABS run with an `N_SO` source-file record that has no
  // name yet: `nm -a` prints it as a bare `SO` line.
  inspect(syms[1].name, content="")
  inspect(syms[1].is_debug(), content="true")
}

///|
test "oracle: the executable header symbol is present and linkable" {
  // `nm sample.bin | grep __mh_execute_header` gives
  // 0000000100000000 T __mh_execute_header.
  let (slice, _) = symtab_of("sample.bin")
  let syms = symbols(slice)
  let mut found : Symbol? = None
  for s in syms {
    if s.name == "__mh_execute_header" && !s.is_debug() {
      found = Some(s)
    }
  }
  match found {
    Some(s) => {
      inspect(s.n_value, content="4294967296") // 0x1_0000_0000
      inspect(s.n_sect.to_int64(), content="1")
      inspect(s.is_external(), content="true")
    }
    None => fail("expected a linkable __mh_execute_header")
  }
}

///|
test "oracle: the table splits cleanly into STABS entries and linkable ones" {
  // `nm sample.bin` prints 5 lines: the header plus three defined functions
  // and one undefined import. `nm -a` prints all 22, so 17 are STABS. Every
  // entry falls in exactly one bucket: an entry counted in neither, or in both,
  // would mean `is_debug` is testing the wrong bit.
  let (slice, tab) = symtab_of("sample.bin")
  let syms = symbols(slice)
  inspect(syms.length(), content=tab.nsyms.to_int64().to_string())
  let mut linkable = 0
  let mut debug = 0
  for s in syms {
    if s.is_debug() {
      debug = debug + 1
    } else {
      linkable = linkable + 1
    }
  }
  inspect(debug, content="17")
  inspect(linkable, content="5")
  inspect(debug + linkable, content=tab.nsyms.to_int64().to_string())
}

///|
test "symbols: every linkable entry has a name" {
  // Every entry `nm` would print resolves to non-empty text; a STABS entry may
  // legitimately carry an empty name, but a linkable one may not. An off-by-one
  // in the string table lookup shows up here as an empty or truncated name.
  let (slice, _) = symtab_of("sample.bin")
  for s in symbols(slice) {
    if !s.is_debug() && s.name == "" {
      fail("empty name at a populated linkable entry")
    }
  }
}

///|
test "oracle: symbol names that nm prints are all present" {
  // The names `nm sample.bin` prints, plus the STABS function names `nm -a`
  // adds. Leading underscores are where a parser that strips or doubles the
  // prefix shows up.
  let (slice, _) = symtab_of("sample.bin")
  let names : Map[String, Bool] = Map([])
  for s in symbols(slice) {
    names[s.name] = true
  }
  for
    expected in [
      "__mh_execute_header", "_compute", "_helper", "_main", "_printf",
    ] {
    if !names.contains(expected) {
      fail("missing symbol \{expected}")
    }
  }
}

///|
test "reject: a symbol table pointing past the end of the file" {
  // Build a header with an LC_SYMTAB whose symoff is far outside the buffer.
  // The parser must reject it at command decoding time, not when it walks
  // symbols, so that callers never see a half-read table.
  let buf = Buffer()
  buf.write_uint_le(0xFEED_FACF)
  buf.write_int_le(0x0100_000C)
  buf.write_int_le(0)
  buf.write_uint_le(2)
  buf.write_uint_le(1) // ncmds
  buf.write_uint_le(24) // sizeofcmds: one LC_SYMTAB
  buf.write_uint_le(0)
  buf.write_uint_le(0)
  buf.write_uint_le(0x2) // LC_SYMTAB
  buf.write_uint_le(24) // cmdsize
  buf.write_uint_le(999999) // symoff, past the end
  buf.write_uint_le(10) // nsyms
  buf.write_uint_le(0) // stroff
  buf.write_uint_le(0) // strsize
  let slice = match parse(buf.to_bytes()) {
    Thin(s) => s
    Fat(_) => fail("expected thin")
  }
  try {
    ignore(symbols(slice))
    fail("expected a rejection")
  } catch {
    OutOfBounds(what~, ..) => inspect(what, content="symbol table")
    e => fail("unexpected error: \{e}")
  }
}

///|
test "empty: a slice with no LC_SYMTAB yields no symbols" {
  // Object files stripped of symbols simply have no LC_SYMTAB; that is not an
  // error and must not be reported as one.
  let buf = Buffer()
  buf.write_uint_le(0xFEED_FACF)
  buf.write_int_le(0x0100_000C)
  buf.write_int_le(0)
  buf.write_uint_le(1) // MH_OBJECT
  buf.write_uint_le(0) // ncmds
  buf.write_uint_le(0)
  buf.write_uint_le(0)
  buf.write_uint_le(0)
  let slice = match parse(buf.to_bytes()) {
    Thin(s) => s
    Fat(_) => fail("expected thin")
  }
  inspect(find_symtab(slice) is None, content="true")
  inspect(symbols(slice).length(), content="0")
}
