// Differential tests for the export trie, against `dyld_info -exports`.
//
// The oracle prints each exported symbol's name and its offset from the image
// base. `sample.bin` exports three symbols, which is more interesting than the
// single `__mh_execute_header` a fully stripped system binary exports: the
// names share a prefix and the trie therefore has more than one level.

///|
/// The export trie of a thin fixture.
fn exports_of(name : String) -> Array[Export] raise {
  let slice = match parse(fixture_bytes(name)) {
    Thin(s) => s
    Fat(_) => fail("expected thin")
  }
  exports(slice)
}

///|
test "oracle: the region matches otool's LC_DYLD_EXPORTS_TRIE" {
  // otool -l sample.bin: LC_DYLD_EXPORTS_TRIE dataoff 32864, datasize 64.
  let slice = match parse(fixture_bytes("sample.bin")) {
    Thin(s) => s
    Fat(_) => fail("expected thin")
  }
  let region = match export_trie(slice) {
    Some(r) => r
    None => fail("expected an export trie")
  }
  inspect(region.offset, content="32864")
  inspect(region.size, content="64")
}

///|
test "oracle: the export trie lists exactly dyld_info's three symbols" {
  // dyld_info -exports sample.bin:
  //   0x00000000  __mh_execute_header
  //   0x00000460  _compute
  //   0x000004E0  _main
  let list = exports_of("sample.bin")
  inspect(list.length(), content="3")
  // The trie walk order is not the file order, so compare as a set by name.
  let by_name : Map[String, Int64] = Map([])
  for e in list {
    by_name[e.name] = e.address.reinterpret_as_int64()
  }
  inspect(by_name["__mh_execute_header"], content="0")
  inspect(by_name["_compute"], content="1120") // 0x460
  inspect(by_name["_main"], content="1248") // 0x4e0
  // All three are regular, strong, non-re-exported definitions.
  for e in list {
    inspect(e.is_reexport(), content="false")
    inspect(e.is_weak(), content="false")
    inspect(e.kind().reinterpret_as_int64(), content="0") // KIND_REGULAR
  }
}

///|
test "oracle: the x86_64 slice exports the same names at its own offsets" {
  // dyld_info -exports on the x86_64 slice of sample.fat:
  //   0x00000000  __mh_execute_header
  //   0x00000470  _compute
  //   0x000004D0  _main
  // The offsets differ from the arm64 slice's, so a walk that ignored the
  // slice's position in the fat file would still agree on the names but not on
  // the addresses.
  let slices = match parse(fixture_bytes("sample.fat")) {
    Fat(s) => s
    Thin(_) => fail("expected fat")
  }
  let list = exports(slices[0].image)
  inspect(list.length(), content="3")
  let by_name : Map[String, Int64] = Map([])
  for e in list {
    by_name[e.name] = e.address.reinterpret_as_int64()
  }
  inspect(by_name["__mh_execute_header"], content="0")
  inspect(by_name["_compute"], content="1136") // 0x470
  inspect(by_name["_main"], content="1232") // 0x4d0
}

///|
test "exports: addresses agree with the symbol table" {
  // The same functions appear in LC_SYMTAB with their virtual addresses. The
  // trie stores an offset from the image base, so the two must differ by
  // exactly the base — which the __TEXT segment names.
  let slice = match parse(fixture_bytes("sample.bin")) {
    Thin(s) => s
    Fat(_) => fail("expected thin")
  }
  let segs = segments(slice)
  let base = segs[1].vmaddr // __TEXT
  let syms = symbols(slice)
  let trie = exports(slice)
  let mut checked = 0
  for e in trie {
    for s in syms {
      if s.name == e.name && !s.is_debug() && s.n_value != 0L {
        inspect(
          s.n_value,
          content=(base + e.address.reinterpret_as_int64()).to_string(),
        )
        checked = checked + 1
      }
    }
  }
  if checked == 0 {
    fail("expected exported symbols to also appear in the symbol table")
  }
}

///|
test "export trie: a region clipped to one byte is rejected, not truncated" {
  // A malformed child offset must be reported rather than followed off the end
  // of the trie. Swapping in a one-byte region makes every child offset invalid.
  let slice = match parse(fixture_bytes("sample.bin")) {
    Thin(s) => s
    Fat(_) => fail("expected thin")
  }
  let region = match export_trie(slice) {
    Some(r) => r
    None => fail("expected a trie")
  }
  // Re-derive a slice whose bounds cover only the first bytes of the trie, so
  // the walk cannot wander into unrelated bytes.
  let tight = MachSlice::{
    header: slice.header,
    commands: slice.commands,
    bounds: Bounds::{
      bytes: slice.bounds.bytes,
      start: region.offset,
      limit: region.offset + 2L,
    },
  }
  // The trie's declared child offsets now point past the readable range, so the
  // walk must fail rather than return a truncated symbol list.
  let outcome = Ok(exports(tight)) catch { e => Err(e) }
  match outcome {
    Ok(_) => fail("expected a rejection for a clipped trie")
    Err(_) => ()
  }
}
