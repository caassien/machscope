// Tests for the parts of the command line that are pure.
//
// `main` itself reads a file and prints, which is the job of the integration
// runs in the README rather than of a unit test. What is worth pinning down is
// the argument parsing — it decides which mode a run uses, and getting it wrong
// silently reports the wrong thing about a file instead of failing.

///|
test "args: each long flag selects its mode" {
  let cases : Array[(String, Subcommand)] = [
    ("--commands", Commands),
    ("--symbols", Symbols),
    ("--sections", Sections),
    ("--signature", Signature),
    ("--entitlements", Entitlements),
    ("--exports", Exports),
    ("--fixups", Fixups),
  ]
  for pair in cases {
    let (flag, want) = pair
    let (got, path) = parse_args([flag, "file.bin"])
    inspect(got == want, content="true")
    inspect(path is Some("file.bin"), content="true")
  }
}

///|
test "args: the short flags are the same modes as the long ones" {
  let cases : Array[(String, Subcommand)] = [
    ("-c", Commands),
    ("-s", Symbols),
    ("-S", Sections),
    ("-g", Signature),
    ("-E", Entitlements),
    ("-e", Exports),
    ("-f", Fixups),
  ]
  for pair in cases {
    let (flag, want) = pair
    let (got, _) = parse_args([flag, "file.bin"])
    inspect(got == want, content="true")
  }
}

///|
test "args: a hex argument becomes a lookup, and the next word is the path" {
  // The CLI takes `machscope 0x100000490 file.dsym`, so an argument starting
  // with 0x is an address and must not be mistaken for the file name.
  let (mode, path) = parse_args(["0x100000490", "file.dsym"])
  inspect(mode == Lookup(0x100000490L), content="true")
  inspect(path is Some("file.dsym"), content="true")
}

///|
test "args: no arguments reports help rather than failing" {
  let (mode, path) = parse_args([])
  inspect(mode == Header, content="true")
  inspect(path is None, content="true")
}

///|
test "args: --help wins over everything after it" {
  let (mode, path) = parse_args(["--sections", "--help", "file.bin"])
  inspect(mode == Help, content="true")
  inspect(path is None, content="true")
}

///|
test "args: --json is never taken as a file path" {
  let (_, path) = parse_args(["--json", "file.bin"])
  inspect(path is Some("file.bin"), content="true")
}

///|
test "args: a flag repeated keeps the last one" {
  let (mode, _) = parse_args(["--symbols", "--sections", "f"])
  inspect(mode == Sections, content="true")
}

///|
test "json: wants_json finds the flag anywhere in the list" {
  inspect(wants_json(["--json"]), content="true")
  inspect(wants_json(["f", "--json"]), content="true")
  inspect(wants_json(["f"]), content="false")
}

///|
test "hex: parse_hex reads the digits after the prefix" {
  inspect(parse_hex("0x0"), content="0")
  inspect(parse_hex("0x10"), content="16")
  inspect(parse_hex("0x100000490"), content="4294968464")
  // Uppercase digits are the same value as lowercase.
  inspect(parse_hex("0xABC"), content="2748")
  inspect(parse_hex("0xabc"), content="2748")
}

///|
test "header: the summary line names the architecture and the header kind" {
  let buf = Buffer()
  buf.write_uint_le(0xFEED_FACF) // MH_MAGIC_64
  buf.write_int_le(0x0100_000C) // CPU_TYPE_ARM64
  buf.write_int_le(2) // CPU_SUBTYPE_ARM64E
  buf.write_uint_le(2) // MH_EXECUTE
  buf.write_uint_le(0) // ncmds
  buf.write_uint_le(0) // sizeofcmds
  buf.write_uint_le(0x00200085) // flags
  buf.write_uint_le(0) // reserved
  let slice = match @lib.parse(buf.to_bytes()) {
    @lib.Thin(s) => s
    @lib.Fat(_) => fail("expected thin")
  }
  let lines = header_lines("arm64", slice.header)
  inspect(lines.length(), content="5")
  inspect(lines[0], content="arm64:")
  // The first line must name arm64 and the 64-bit magic; a parser that
  // reported the raw cputype integer here would make the summary unreadable.
  inspect(lines[1].contains("arm64"), content="true")
  inspect(lines[1].contains("MH_MAGIC_64"), content="true")
  inspect(lines[1].contains("little-endian"), content="true")
}

///|
test "fixups: the printed lines name the kind the way dyld_info does" {
  // A lazy bind and a plain bind look the same in the struct apart from the
  // `is_lazy` flag, and `dyld_info` labels them differently for a reason: a
  // lazy slot is not resolved until the first call through it. Rendering both
  // as `bind` would tell a reader the loader patches that slot at launch.
  let binds : Array[@lib.Fixup] = [
    @lib.Fixup::{
      address: 0x1_0000_4000L,
      target: 0L,
      import_index: Some(0L),
      symbol: Some("_printf"),
      library_ordinal: 1U,
      key: 0U,
      diversity: 0U,
      has_discriminator: false,
      is_lazy: false,
    },
    @lib.Fixup::{
      address: 0x1_0000_5000L,
      target: 0L,
      import_index: Some(1L),
      symbol: Some("_puts"),
      library_ordinal: 2U,
      key: 0U,
      diversity: 0U,
      has_discriminator: false,
      is_lazy: true,
    },
    @lib.Fixup::{
      address: 0x1_0000_6000L,
      target: 0x1_0000_0123L,
      import_index: None,
      symbol: None,
      library_ordinal: 0U,
      key: 0U,
      diversity: 0U,
      has_discriminator: false,
      is_lazy: false,
    },
  ]
  let lines = fixup_lines(binds)
  inspect(lines.length(), content="3")
  inspect(lines[0], content="  0x100004000 bind _printf (lib 1)")
  inspect(lines[1], content="  0x100005000 lazy-bind _puts (lib 2)")
  inspect(lines[2], content="  0x100006000 rebase -> 0x100000123")
}
