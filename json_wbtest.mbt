// Tests for the JSON report.
//
// The report is a contract: a script reading it depends on the key names and on
// the areas being quoted as hex strings, so both are asserted rather than left
// to inspection.

///|
/// Parses a fixture and builds its JSON report.
///
/// `fixups_` is a parameter rather than always-on because the earlier version
/// of this helper never requested it, which is how `file_report`'s Fat branch
/// dropping the flag went unnoticed: no test ever asked a fat file for its
/// fixups in JSON.
fn report_of(
  name : String,
  segments_~ : Bool = false,
  fixups_~ : Bool = false,
) -> Json raise {
  let file = parse(fixture_bytes(name))
  file_report(file, segments_~, symbols_=true, exports_=true, fixups_~)
}

///|
test "json: a thin file reports one architecture" {
  let j = report_of("sample.bin")
  let archs = match j {
    Object(m) =>
      match m.get("architectures") {
        Some(Array(list)) => list
        _ => fail("architectures is not an array")
      }
    _ => fail("report is not an object")
  }
  inspect(archs.length(), content="1")
}

///|
test "json: a fat file reports one architecture per slice" {
  let j = report_of("sample.fat")
  let archs = match j {
    Object(m) =>
      match m.get("architectures") {
        Some(Array(list)) => list
        _ => fail("no architectures")
      }
    _ => fail("report is not an object")
  }
  inspect(archs.length(), content="2")
  // Each entry names the slice's own architecture and the byte range it
  // occupies in the fat file. `otool -f sample.fat` reports the x86_64 slice
  // first, at offset 4096 with size 8816 and align 2^12.
  let first = archs[0]
  match first {
    Object(m) => {
      match m.get("fat_cpu_type") {
        Some(Number(n, ..)) => inspect(n.to_int(), content="16777223")
        _ => fail("no fat_cpu_type")
      }
      match m.get("fat_offset") {
        Some(Number(n, ..)) => inspect(n.to_int(), content="4096")
        _ => fail("no fat_offset")
      }
      match m.get("fat_size") {
        Some(Number(n, ..)) => inspect(n.to_int(), content="8816")
        _ => fail("no fat_size")
      }
      match m.get("fat_align") {
        Some(Number(n, ..)) => inspect(n.to_int(), content="12")
        _ => fail("no fat_align")
      }
    }
    _ => fail("architecture entry is not an object")
  }
  // The second entry is the arm64 slice, at offset 16384 with size 33808.
  match archs[1] {
    Object(m) => {
      match m.get("fat_cpu_type") {
        Some(Number(n, ..)) => inspect(n.to_int(), content="16777228")
        _ => fail("no fat_cpu_type")
      }
      match m.get("fat_offset") {
        Some(Number(n, ..)) => inspect(n.to_int(), content="16384")
        _ => fail("no fat_offset")
      }
      match m.get("fat_size") {
        Some(Number(n, ..)) => inspect(n.to_int(), content="33808")
        _ => fail("no fat_size")
      }
    }
    _ => fail("architecture entry is not an object")
  }
}

///|
test "json: the header fields match the parser" {
  let j = report_of("sample.bin")
  let archs = match j {
    Object(m) =>
      match m.get("architectures") {
        Some(Array(list)) => list
        _ => fail("no architectures")
      }
    _ => fail("report is not an object")
  }
  let header = match archs[0] {
    Object(m) =>
      match m.get("header") {
        Some(Object(h)) => h
        _ => fail("no header")
      }
    _ => fail("architecture is not an object")
  }
  // sample.bin has 17 load commands, as otool -h reports.
  match header.get("ncmds") {
    Some(Number(n, ..)) => inspect(n.to_int(), content="17")
    _ => fail("no ncmds")
  }
  match header.get("magic") {
    Some(String(m)) => inspect(m, content="MH_MAGIC_64")
    _ => fail("no magic")
  }
  match header.get("cpu_type") {
    Some(Number(n, ..)) => inspect(n.to_int(), content="16777228")
    _ => fail("no cpu_type")
  }
}

///|
test "json: addresses are hex strings so no precision is lost" {
  // A JSON number would round-trip a 64-bit address through a double, which
  // silently corrupts addresses above 2^53. They are strings for this reason.
  let j = report_of("sample.bin")
  let symbols = match j {
    Object(m) =>
      match m.get("architectures") {
        Some(Array(archs)) =>
          match archs[0] {
            Object(a) =>
              match a.get("symbols") {
                Some(Array(list)) => list
                _ => fail("no symbols")
              }
            _ => fail("architecture is not an object")
          }
        _ => fail("no architectures")
      }
    _ => fail("report is not an object")
  }
  let mut found = false
  for s in symbols {
    match s {
      Object(m) =>
        match m.get("address") {
          // `nm sample.bin` gives _compute the address 0x100000460.
          Some(String(a)) => if a == "0x100000460" { found = true }
          _ => fail("address is not a string")
        }
      _ => fail("symbol is not an object")
    }
  }
  if !found {
    fail("expected the compute function's address as a hex string")
  }
}

///|
test "json: segments are omitted unless asked for" {
  // The report is built lazily so that a caller wanting only the header does
  // not pay for a full segment walk.
  let first_arch = fn(j : Json) -> Json raise {
    match j {
      Object(m) =>
        match m.get("architectures") {
          Some(Array(list)) => list[0]
          _ => fail("no architectures")
        }
      _ => fail("report is not an object")
    }
  }
  let without = first_arch(report_of("sample.bin"))
  match without {
    Object(m) =>
      match m.get("segments") {
        None => ()
        Some(_) => fail("segments present when not requested")
      }
    _ => fail("architecture is not an object")
  }
  let having = first_arch(report_of("sample.bin", segments_=true))
  let segs = match having {
    Object(m) =>
      match m.get("segments") {
        Some(Array(s)) => s
        _ => fail("segments missing when requested")
      }
    _ => fail("architecture is not an object")
  }
  // The sample has __PAGEZERO, __TEXT, __DATA_CONST, __LINKEDIT.
  inspect(segs.length(), content="4")
}

///|
test "json: a lookup reports the source position dwarfdump gives" {
  // `dwarfdump --debug-line sample.dsym` lists 0x0000000100000490 at line 12,
  // column 21.
  let j = file_lookup_report(
    parse(fixture_bytes("sample.dsym")),
    0x1_0000_0490L,
  )
  let locations = match j {
    Object(m) =>
      match m.get("lookup") {
        Some(Array(archs)) =>
          match archs[0] {
            Object(a) =>
              match a.get("locations") {
                Some(Array(list)) => list
                _ => fail("no locations")
              }
            _ => fail("lookup entry is not an object")
          }
        _ => fail("no lookup key")
      }
    _ => fail("report is not an object")
  }
  inspect(locations.length(), content="1")
  match locations[0] {
    Object(m) => {
      match m.get("file") {
        Some(String(f)) => inspect(f, content="sample.c")
        _ => fail("no file")
      }
      match m.get("line") {
        Some(Number(n, ..)) => inspect(n.to_int(), content="12")
        _ => fail("no line")
      }
      match m.get("column") {
        Some(Number(n, ..)) => inspect(n.to_int(), content="21")
        _ => fail("no column")
      }
    }
    _ => fail("location is not an object")
  }
}

///|
test "json: an address with no line information reports an empty list" {
  // The key is present with an empty array, so a caller can distinguish "asked
  // and got nothing" from "never asked".
  let j = file_lookup_report(parse(fixture_bytes("sample.dsym")), 0x100L)
  let locations = match j {
    Object(m) =>
      match m.get("lookup") {
        Some(Array(archs)) =>
          match archs[0] {
            Object(a) =>
              match a.get("locations") {
                Some(Array(list)) => list
                _ => fail("no locations key")
              }
            _ => fail("lookup entry is not an object")
          }
        _ => fail("no lookup key")
      }
    _ => fail("report is not an object")
  }
  inspect(locations.length(), content="0")
}

///|
test "json: the report round-trips through the parser" {
  // Serializing and re-parsing proves the output is valid JSON, not merely
  // a string that looks like it.
  let j = report_of("sample.fat")
  let text = j.stringify()
  let parsed = Ok(@json.parse(text)) catch { e => Err(e) }
  match parsed {
    Ok(_) => ()
    Err(e) => fail("output is not valid JSON: \{e.to_string()}")
  }
}

///|
test "json: a thin file reports its fixups when asked" {
  let j = report_of("sample.bin", fixups_=true)
  let archs = match j {
    Object(m) =>
      match m.get("architectures") {
        Some(Array(list)) => list
        _ => fail("no architectures")
      }
    _ => fail("report is not an object")
  }
  let fixups = match archs[0] {
    Object(a) =>
      match a.get("fixups") {
        Some(Array(f)) => f
        _ => fail("no fixups key")
      }
    _ => fail("architecture is not an object")
  }
  inspect(fixups.length(), content="1")
  match fixups[0] {
    Object(f) => {
      // The one fixup in `sample.bin` is the `_printf` bind at 0x100004000.
      match f.get("address") {
        Some(String(a)) => inspect(a, content="0x100004000")
        _ => fail("fixup address is not a hex string")
      }
      match f.get("kind") {
        Some(String(k)) => inspect(k, content="bind")
        _ => fail("no kind")
      }
      match f.get("symbol") {
        Some(String(s)) => inspect(s, content="_printf")
        _ => fail("no symbol")
      }
    }
    _ => fail("fixup is not an object")
  }
}

///|
test "json: a fat file reports each slice's fixups" {
  // This is the case the Fat branch of `file_report` used to drop: it passed
  // `segments_`, `symbols_` and `exports_` down to `slice_report` and forgot
  // `fixups_`, so `--json --fixups` on a universal binary printed the header
  // and nothing else. A thin file still worked, so it took a fat fixture to see.
  let j = report_of("sample.fat", fixups_=true)
  let archs = match j {
    Object(m) =>
      match m.get("architectures") {
        Some(Array(list)) => list
        _ => fail("no architectures")
      }
    _ => fail("report is not an object")
  }
  inspect(archs.length(), content="2")
  for arch in archs {
    match arch {
      Object(a) =>
        match a.get("fixups_error") {
          Some(_) => fail("fixup walk failed on a fixture that should decode")
          None => ()
        }
      _ => fail("architecture is not an object")
    }
  }
  match archs[1] {
    Object(a) =>
      match a.get("fixups") {
        Some(Array(f)) => {
          inspect(f.length(), content="1")
          match f[0] {
            Object(fx) =>
              match fx.get("address") {
                Some(String(addr)) => inspect(addr, content="0x100004000")
                _ => fail("fixup address is not a hex string")
              }
            _ => fail("fixup is not an object")
          }
        }
        _ => fail("the arm64 slice has no fixups key")
      }
    _ => fail("architecture is not an object")
  }
}

///|
test "json: a classic dyld-info image reports its fixups too" {
  // The two encodings share the same JSON shape, so a consumer does not have
  // to know which one produced the file.
  let j = report_of("sample.classic", fixups_=true)
  let archs = match j {
    Object(m) =>
      match m.get("architectures") {
        Some(Array(list)) => list
        _ => fail("no architectures")
      }
    _ => fail("report is not an object")
  }
  let fixups = match archs[0] {
    Object(a) =>
      match a.get("fixups") {
        Some(Array(f)) => f
        _ => fail("no fixups key")
      }
    _ => fail("architecture is not an object")
  }
  inspect(fixups.length(), content="6")
  // `kind` has to distinguish a lazy bind, or a consumer cannot tell which
  // slots dyld resolves at launch.
  let kinds : Map[String, Int32] = Map([])
  for f in fixups {
    match f {
      Object(o) =>
        match o.get("kind") {
          Some(String(k)) =>
            match kinds.get(k) {
              Some(n) => kinds[k] = n + 1
              None => kinds[k] = 1
            }
          _ => fail("no kind")
        }
      _ => fail("fixup is not an object")
    }
  }
  inspect(kinds["rebase"], content="4")
  inspect(kinds["bind"], content="1")
  inspect(kinds["lazy-bind"], content="1")
}
