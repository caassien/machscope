// Parser benchmarks.
//
// Run with `moon run bench`. Each line reports the mean time of one operation
// over a fixed number of iterations, so a regression in the hot path shows up
// as a number rather than as an impression.

///|
/// Reads a fixture by name.
fn load(name : String) -> Bytes raise {
  let dir = @env.current_dir().unwrap()
  @fs.read_file_to_bytes(dir + "/internal/fixtures/" + name)
}

///|
/// Entry point.
///
/// Fixtures are read once here rather than in a top-level `let`, which cannot
/// raise.
fn main raise {
  let thin_x86 = load("ls.x86_64.macho")
  let fat_ls = load("ls.fat.macho")
  let dsym = load("sample.dsym")
  println("fixture              operation                mean")
  report("ls.x86_64.macho", "parse (header+commands)", fn() raise {
    ignore(@lib.parse(thin_x86))
  })
  report("ls.x86_64.macho", "segments", fn() raise {
    match @lib.parse(thin_x86) {
      Thin(s) => ignore(@lib.segments(s))
      Fat(_) => ()
    }
  })
  report("ls.x86_64.macho", "symbols", fn() raise {
    match @lib.parse(thin_x86) {
      Thin(s) => ignore(@lib.symbols(s))
      Fat(_) => ()
    }
  })
  report("ls.fat.macho", "parse both slices", count=20U, fn() raise {
    ignore(@lib.parse(fat_ls))
  })
  report("ls.fat.macho", "exports, both slices", fn() raise {
    match @lib.parse(fat_ls) {
      Fat(slices) =>
        for s in slices {
          ignore(@lib.exports(s.image))
        }
      Thin(s) => ignore(@lib.exports(s))
    }
  })
  report("sample.dsym", "line tables", count=20U, fn() raise {
    match @lib.parse(dsym) {
      Thin(s) => ignore(@lib.line_tables(s, comp_dir="/tmp"))
      Fat(_) => ()
    }
  })
  report("sample.dsym", "address lookup", count=20U, fn() raise {
    match @lib.parse(dsym) {
      Thin(s) => {
        let tables = @lib.line_tables(s, comp_dir="/tmp")
        for t in tables {
          ignore(@lib.lookup_address(t, 0x1_0000_0490L))
        }
      }
      Fat(_) => ()
    }
  })
}

///|
/// Benchmarks one operation and prints its timing.
///
/// `Bench` renders its own summary, which avoids depending on the layout of a
/// type the benchmark package keeps abstract. The iteration count is fixed
/// rather than time-based so a slow machine takes the same number of samples as
/// a fast one.
fn report(
  label : String,
  op : String,
  count~ : UInt32 = 50U,
  f : () -> Unit raise?,
) -> Unit {
  let b = @core_bench.Bench()
  b.bench(name="\{label}  \{op}", count~, () => f() catch { _ => () })
  // `dump_summaries` renders JSON, which is convenient for a machine and
  // unreadable in a terminal. Pull the two fields a reader wants out of it.
  let text = b.dump_summaries()
  let parsed = Ok(@json.parse(text)) catch { _ => Err(()) }
  match parsed {
    Ok(entries) =>
      match entries {
        Array(list) =>
          for entry in list {
            match entry {
              Object(m) => {
                let name = match m.get("name") {
                  Some(String(n)) => n
                  _ => ""
                }
                let mean = match m.get("mean") {
                  Some(Number(n, ..)) => n
                  _ => 0.0
                }
                // `mean` is already in microseconds.
                println(pad(name, 50) + format_us(mean))
              }
              _ => ()
            }
          }
        _ => println(text)
      }
    Err(_) => println(text)
  }
}

///|
/// Right-pads a label so the columns line up.
fn pad(s : String, width : Int32) -> String {
  let buf = StringBuilder()
  buf.write_string(s)
  let mut i = s.length()
  while i < width {
    buf.write_char(' ')
    i = i + 1
  }
  buf.to_string()
}

///|
/// Formats a microsecond count with three decimal places.
fn format_us(us : Double) -> String {
  let whole = (us * 1000.0).to_int() / 1000
  let frac = (us * 1000.0).to_int() % 1000
  let frac_text = if frac < 10 {
    "00\{frac}"
  } else if frac < 100 {
    "0\{frac}"
  } else {
    frac.to_string()
  }
  "\{whole}.\{frac_text} us"
}
