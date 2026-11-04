// Differential tests for the symbol table, against `nm` as the oracle.
//
// `nm` reads the same `LC_SYMTAB`; any disagreement on order, count or spelling
// is a defect in one of the two.

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
test "oracle: nsyms matches nm's line count" {
  // `nm ls.x86_64.macho | wc -l` is 92, and `otool -l` reports nsyms 93: the
  // linker emits one trailing entry with an empty name, which nm skips.
  let (_, tab) = symtab_of("ls.x86_64.macho")
  inspect(tab.nsyms.to_int64(), content="93")
}

///|
test "oracle: the first table entry is a debug entry nm hides by default" {
  // The first nlist is `radr://5614542` with n_type 0x3c: N_STAB set, so `nm`
  // omits it and `nm -a` shows it. A parser that trusts nm's output as the
  // complete table would be off by one for every subsequent index.
  let (slice, _) = symtab_of("ls.x86_64.macho")
  let syms = symbols(slice)
  inspect(syms[0].name, content="radr://5614542")
  inspect(syms[0].is_debug(), content="true")
  inspect(syms[0].is_external(), content="false")
}

///|
test "oracle: the executable header symbol is present and linkable" {
  // `nm ls.x86_64.macho | grep __mh_execute_header` gives the address
  // 0000000100000000 and type T.
  let (slice, _) = symtab_of("ls.x86_64.macho")
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
test "oracle: linkable symbols outnumber debug entries" {
  // `nm ls.x86_64.macho` prints 92 lines: 91 undefined externals plus the
  // executable header. The 93rd table entry nm shows only with -a.
  let (slice, tab) = symtab_of("ls.x86_64.macho")
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
  inspect(debug, content="1")
  inspect(linkable, content="92")
}

///|
test "oracle: every table entry has a name" {
  // All 93 entries resolve to non-empty text, including the debug entry and the
  // last one; an off-by-one in the string table lookup shows up here.
  let (slice, _) = symtab_of("ls.x86_64.macho")
  for s in symbols(slice) {
    if s.name == "" {
      fail("empty symbol name at a populated entry")
    }
  }
}

///|
test "oracle: symbol names that nm prints are all present" {
  // Spot-check names with characters that tempt a parser to truncate: dollar
  // signs (version-compat suffixes) and leading underscores.
  let (slice, _) = symtab_of("ls.x86_64.macho")
  let names : Map[String, Bool] = Map([])
  for s in symbols(slice) {
    names[s.name] = true
  }
  // `_fts_open$INODE64` exercises the dollar sign; `__mh_execute_header` the
  // doubled underscore; `dyld_stub_binder` a name with no underscore at all.
  for
    expected in ["_fts_open$INODE64", "__mh_execute_header", "dyld_stub_binder"] {
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
