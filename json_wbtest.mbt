// Tests for the JSON report.
//
// The report is a contract: a script reading it depends on the key names and on
// the areas being quoted as hex strings, so both are asserted rather than left
// to inspection.

///|
/// Parses a fixture and builds its JSON report.
fn report_of(name : String, segments_~ : Bool = false) -> Json raise {
  let file = parse(fixture_bytes(name))
  let _ = segments_
  file_report(file, segments_~, symbols_=true, exports_=true)
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
  let j = report_of("ls.fat.macho")
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
  // occupies in the fat file.
  let first = archs[0]
  match first {
    Object(m) => {
      match m.get("fat_cpu_type") {
        Some(Number(n, ..)) => inspect(n.to_int(), content="16777223")
        _ => fail("no fat_cpu_type")
      }
      match m.get("fat_offset") {
        Some(Number(n, ..)) => inspect(n.to_int(), content="16384")
        _ => fail("no fat_offset")
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
          Some(String(a)) => if a == "0x100000460" { found = true }
          _ => fail("address is not a string")
        }
      _ => fail("symbol is not an object")
    }
  }
  if !found {
    fail("expected the helper function's address as a hex string")
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
  // The sample has __PAGEZERO, __TEXT, __DATA, __LINKEDIT.
  inspect(segs.length(), content="4")
}

///|
test "json: a lookup reports the source position dwarfdump gives" {
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
        Some(String(f)) => inspect(f, content="t.c")
        _ => fail("no file")
      }
      match m.get("line") {
        Some(Number(n, ..)) => inspect(n.to_int(), content="3")
        _ => fail("no line")
      }
      match m.get("column") {
        Some(Number(n, ..)) => inspect(n.to_int(), content="33")
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
  let j = report_of("ls.x86_64.macho")
  let text = j.stringify()
  let parsed = Ok(@json.parse(text)) catch { e => Err(e) }
  match parsed {
    Ok(_) => ()
    Err(e) => fail("output is not valid JSON: \{e.to_string()}")
  }
}
