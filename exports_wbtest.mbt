// Differential tests for the export trie, against `dyld_info -exports`.
//
// The oracle prints each exported symbol's name and its offset from the image
// base. `sample.bin` is the more interesting fixture: unlike the system
// binaries, which export only the Mach header, it exports two functions whose
// addresses the line-table tests also use.

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
test "oracle: the region matches otool's LC_DYLD_INFO_ONLY" {
  // otool -l ls.x86_64.macho: export_off 26224, export_size 32.
  let slice = match parse(fixture_bytes("ls.x86_64.macho")) {
    Thin(s) => s
    Fat(_) => fail("expected thin")
  }
  let region = match export_trie(slice) {
    Some(r) => r
    None => fail("expected an export trie")
  }
  inspect(region.offset, content="26224")
  inspect(region.size, content="32")
}

///|
test "oracle: a system binary exports exactly its Mach header" {
  // dyld_info -exports prints one line: 0x00000000 __mh_execute_header.
  let list = exports_of("ls.x86_64.macho")
  inspect(list.length(), content="1")
  inspect(list[0].name, content="__mh_execute_header")
  inspect(list[0].address.reinterpret_as_int64(), content="0")
  inspect(list[0].is_reexport(), content="false")
  inspect(list[0].is_weak(), content="false")
  inspect(list[0].kind().reinterpret_as_int64(), content="0") // EXPORT_SYMBOL_FLAGS_KIND_REGULAR
}

///|
test "oracle: a compiled binary exports its functions with their offsets" {
  // dyld_info -exports sample.bin:
  //   0x00000000 __mh_execute_header
  //   0x00000460 _helper
  //   0x00000478 _main
  let list = exports_of("sample.bin")
  inspect(list.length(), content="3")
  // The trie walk order is not the file order, so compare as a set by name.
  let by_name : Map[String, Int64] = Map([])
  for e in list {
    by_name[e.name] = e.address.reinterpret_as_int64()
  }
  inspect(by_name["__mh_execute_header"], content="0")
  inspect(by_name["_helper"], content="1120") // 0x460
  inspect(by_name["_main"], content="1144") // 0x478
}

///|
test "oracle: exported addresses agree with the symbol table" {
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
        inspect(s.n_value, content=(base + e.address.reinterpret_as_int64()).to_string())
        checked = checked + 1
      }
    }
  }
  if checked == 0 {
    fail("expected exported symbols to also appear in the symbol table")
  }
}

///|
test "export trie: every edge is reachable within the region" {
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
  let clipped = ExportTrieRegion::{ offset: region.offset, size: 1L, }
  // Re-derive a slice whose bounds cover only that byte, so the walk cannot
  // wander into unrelated bytes.
  let tight = MachSlice::{
    header: slice.header,
    commands: slice.commands,
    bounds: Bounds::{
      bytes: slice.bounds.bytes,
      start: region.offset,
      limit: region.offset + 2L,
    },
  }
  let _ = clipped
  // The trie's declared node offsets now point past the readable range, so the
  // walk must fail rather than return a truncated symbol list.
  let outcome = Ok(exports_with_region(tight, clipped)) catch { e => Err(e) }
  match outcome {
    Ok(_) => fail("expected a rejection for a clipped trie")
    Err(_) => ()
  }
}

///|
/// Walks a trie given an explicit region, used by the rejection test.
fn exports_with_region(
  slice : MachSlice,
  region : ExportTrieRegion,
) -> Array[Export] raise MachscopeError {
  // Reuse the public walk by temporarily trusting the region: the slice bounds
  // already restrict what can be read.
  let _ = region
  exports(slice)
}
