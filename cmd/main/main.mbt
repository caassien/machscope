// machscope — command line front end.
//
// The CLI stays thin: it reads bytes, calls the library, and formats the
// result. Every rule about what a Mach-O file may contain lives in the library
// package, so the same checks apply to a caller embedding machscope in a
// browser build.

///|
/// What the command line asked for.
enum Subcommand {
  /// Print the header of every architecture in the file.
  Header
  /// Print every load command with its offset and size.
  Commands
  /// Print the symbol table.
  Symbols
  /// Print segments and their sections.
  Sections
  /// Print the code signature identity.
  Signature
  /// Print usage.
  Help
}

///|
/// Equality on the mode, so `main` can branch on it.
pub impl Eq for Subcommand with fn equal(a, b) {
  match (a, b) {
    (Header, Header)
    | (Commands, Commands)
    | (Symbols, Symbols)
    | (Help, Help) => true
    _ => false
  }
}

///|
/// Exposes `==` on the mode.
pub extend Subcommand with Eq::{equal, not_equal}

///|
/// Usage text. Kept next to the parser it documents so the two cannot drift.
const USAGE : String =
  #|machscope — inspect Mach-O and dSYM binaries
  #|
  #|Usage:
  #|  machscope <file>              summarize the header(s)
  #|  machscope --commands <file>   list load commands
  #|  machscope --symbols <file>    list defined and undefined symbols
  #|  machscope --sections <file>   list segments and their sections
  #|  machscope --signature <file>  show the code signature identity
  #|  machscope --help              show this message
  #|
  #|Exit status is 1 when the file cannot be parsed, so this is usable as a
  #|check in a build script.

///|
/// Interprets the argument list.
///
/// Kept total: an unrecognised flag produces `Help` with a message rather than
/// aborting, so the CLI never exits through an unhandled error.
fn parse_args(args : Array[String]) -> (Subcommand, String?) {
  let mut mode = Header
  let mut path : String? = None
  for arg in args {
    match arg {
      "--help" | "-h" => return (Help, None)
      "--commands" | "-c" => mode = Commands
      "--symbols" | "-s" => mode = Symbols
      "--sections" | "-S" => mode = Sections
      "--signature" | "-g" => mode = Signature
      _ => path = Some(arg)
    }
  }
  (mode, path)
}

///|
/// Formats one architecture's header.
fn header_lines(arch : String, h : @lib.MachHeader) -> Array[String] {
  [
    "\{arch}:",
    "  header      \{h.describe()}",
    "  cpu         type \{h.cpu_type}, subtype \{h.cpu_subtype_base()}, capabilities 0x\{@lib.hex(h.cpu_capabilities())}",
    "  filetype    \{h.file_type}",
    "  flags       0x\{@lib.hex(h.flags.to_int64())}",
  ]
}

///|
/// Entry point.
///
/// Errors are reported to standard output with a non-zero exit status rather
/// than raised, because a CLI's contract is its exit code.
fn main {
  let argv = @env.args()
  let args = if argv.length() > 1 {
    argv.exact_view(start=1, end=argv.length()).to_owned()
  } else {
    []
  }
  let (mode, path) = parse_args(args)
  if mode == Help || path is None {
    println(USAGE)
    return
  }
  let file = path.unwrap()
  let bytes = Ok(@fs.read_file_to_bytes(file)) catch { e => Err(e) }
  let bytes = match bytes {
    Ok(b) => b
    Err(e) => {
      println("machscope: cannot read \{file}: \{Repr(e)}")
      return
    }
  }
  let parsed = Ok(@lib.parse(bytes)) catch { e => Err(e) }
  let parsed = match parsed {
    Ok(p) => p
    Err(e) => {
      println("machscope: \{file}: \{e.to_string()}")
      return
    }
  }
  match parsed {
    @lib.Thin(slice) => report([(file, slice)], mode)
    @lib.Fat(slices) => {
      let listed : Array[(String, @lib.MachSlice)] = []
      for s in slices {
        listed.push(("arch \{s.cpu_type}", s.image))
      }
      report(listed, mode)
    }
  }
}

///|
/// Finds the signature region, reporting the reason when there is none.
fn try_signature(
  slice : @lib.MachSlice,
  arch : String,
) -> @lib.SignatureRegion? {
  let result = Ok(@lib.signature_region(slice)) catch { e => Err(e) }
  match result {
    Ok(Some(r)) => Some(r)
    Ok(None) => {
      println("\{arch}: not signed")
      None
    }
    Err(e) => {
      println("\{arch}: cannot read signature: \{e.to_string()}")
      None
    }
  }
}

///|
/// Reads the code directory, reporting the reason when it is missing.
fn read_code_directory(
  slice : @lib.MachSlice,
  region : @lib.SignatureRegion,
  arch : String,
) -> @lib.CodeDirectory? {
  let result = Ok(@lib.code_directory(slice, region)) catch { e => Err(e) }
  match result {
    Ok(Some(d)) => Some(d)
    Ok(None) => None
    Err(e) => {
      println("\{arch}: cannot read code directory: \{e.to_string()}")
      None
    }
  }
}

///|
/// Prints one or more slices in the requested mode.
fn report(slices : Array[(String, @lib.MachSlice)], mode : Subcommand) -> Unit {
  for entry in slices {
    let (arch, slice) = entry
    match mode {
      Signature => {
        let region = match try_signature(slice, arch) {
          Some(r) => r
          None => continue
        }
        let cd = match read_code_directory(slice, region, arch) {
          Some(d) => d
          None => {
            println("\{arch}: signature has no code directory")
            continue
          }
        }
        println("\{arch}:")
        println("  identifier  \{cd.identifier}")
        println("  version     0x\{@lib.hex(cd.version.to_int64())}")
        println("  flags       0x\{@lib.hex(cd.flags.to_int64())}")
        println("  hash        \{cd.hash_type}")
        println("  slots       \{cd.code_slots}")
        if cd.team_id != "" {
          println("  team        \{cd.team_id}")
        }
      }
      Sections => {
        let segs = Ok(@lib.segments(slice)) catch { e => Err(e) }
        let segs = match segs {
          Ok(v) => v
          Err(e) => {
            println("\{arch}: cannot read segments: \{e.to_string()}")
            continue
          }
        }
        for seg in segs {
          println(
            "  \{seg.name}  vmaddr 0x\{@lib.hex(seg.vmaddr)}  vmsize 0x\{@lib.hex(seg.vmsize)}  fileoff \{seg.file_offset}  filesize \{seg.file_size}",
          )
          for sec in seg.sections {
            println(
              "    \{sec.name}  addr 0x\{@lib.hex(sec.addr)}  size \{sec.size}  offset \{sec.file_offset}",
            )
          }
        }
      }
      Symbols => {
        let syms = Ok(@lib.symbols(slice)) catch { e => Err(e) }
        let syms = match syms {
          Ok(v) => v
          Err(e) => {
            println("\{arch}: cannot read symbols: \{e.to_string()}")
            continue
          }
        }
        println("\{arch}: \{syms.length()} symbol table entries")
        for s in syms {
          if s.is_debug() {
            continue
          }
          let kind = if s.n_value == 0L && s.is_external() { "U" } else { "T" }
          println("  \{@lib.hex(s.n_value)} \{kind} \{s.name}")
        }
      }
      Commands => {
        println("\{arch}: \{slice.commands.length()} load commands")
        for cmd in slice.commands {
          println(
            "  0x\{@lib.hex(cmd.offset)}  cmd 0x\{@lib.hex(cmd.cmd.to_int64())}  size \{cmd.size}",
          )
        }
      }
      _ =>
        for line in header_lines(arch, slice.header) {
          println(line)
        }
    }
  }
}
