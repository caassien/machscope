// Differential tests for the segment and section table, against `otool -l`.

///|
/// The segments of a thin fixture.
fn segments_of(name : String) -> Array[Segment] raise {
  let slice = match parse(fixture_bytes(name)) {
    Thin(s) => s
    Fat(_) => fail("expected thin")
  }
  segments(slice)
}

///|
test "oracle: segment names and order match otool -l" {
  // otool -l lists __PAGEZERO, __TEXT, __DATA, __LINKEDIT in that order.
  let segs = segments_of("ls.x86_64.macho")
  inspect(segs.length(), content="4")
  inspect(segs[0].name, content="__PAGEZERO")
  inspect(segs[1].name, content="__TEXT")
  inspect(segs[2].name, content="__DATA")
  inspect(segs[3].name, content="__LINKEDIT")
}

///|
test "oracle: segment addresses and sizes match otool -l" {
  let segs = segments_of("ls.x86_64.macho")
  // __TEXT: vmaddr 0x100000000, vmsize 0x5000, fileoff 0, filesize 20480
  inspect(segs[1].vmaddr, content="4294967296")
  inspect(segs[1].vmsize, content="20480")
  inspect(segs[1].file_offset, content="0")
  inspect(segs[1].file_size, content="20480")
  // __DATA: vmaddr 0x100005000, vmsize 0x1000, fileoff 20480, filesize 4096
  inspect(segs[2].vmaddr, content="4294987776")
  inspect(segs[2].vmsize, content="4096")
  inspect(segs[2].file_offset, content="20480")
  inspect(segs[2].file_size, content="4096")
  // __PAGEZERO maps a gigabyte of nothing and occupies no file bytes.
  inspect(segs[0].file_size, content="0")
  inspect(segs[0].vmsize, content="4294967296")
}

///|
test "oracle: section names and addresses match otool -l" {
  // The first six sections of __TEXT, in file order.
  let segs = segments_of("ls.x86_64.macho")
  let text = segs[1]
  inspect(text.sections.length(), content="6")
  inspect(text.sections[0].name, content="__text")
  inspect(text.sections[0].addr, content="4294969112") // 0x100000718
  inspect(text.sections[1].name, content="__stubs")
  inspect(text.sections[1].addr, content="4294984207") // 0x10000420f
  inspect(text.sections[2].name, content="__stub_helper")
  inspect(text.sections[3].name, content="__const")
  inspect(text.sections[4].name, content="__cstring")
  inspect(text.sections[5].name, content="__unwind_info")
}

///|
test "oracle: section counts sum to the file's total" {
  // `otool -l ls.x86_64.macho | grep -c sectname` is 12.
  let segs = segments_of("ls.x86_64.macho")
  let mut total = 0
  for seg in segs {
    total = total + seg.sections.length()
  }
  inspect(total, content="12")
}

///|
test "oracle: section segment names repeat the enclosing segment" {
  // A section's own segname field must agree with the segment that owns it; a
  // parser that reads the wrong fixed offset would mix them up.
  let segs = segments_of("ls.x86_64.macho")
  for seg in segs {
    for s in seg.sections {
      inspect(s.segment_name, content=seg.name)
    }
  }
}

///|
test "address to offset: a real section address maps into that section" {
  let segs = segments_of("ls.x86_64.macho")
  let text = match find_section(segs, "__TEXT", "__text") {
    Some(s) => s
    None => fail("expected __TEXT,__text")
  }
  // The section's first byte maps to its own file offset.
  let off = file_offset_of_address(segs, text.addr)
  match off {
    Some(v) => inspect(v, content=text.file_offset.to_int64().to_string())
    None => fail("expected an offset for a section address")
  }
  // An address inside the section maps to the corresponding offset inside it,
  // so that one delta works for the whole section.
  let inside = file_offset_of_address(segs, text.addr + 16L)
  match inside {
    Some(v) =>
      inspect(v, content=(text.file_offset.to_int64() + 16L).to_string())
    None => fail("expected an offset 16 bytes into the section")
  }
}

///|
test "address to offset: zero-fill addresses have no file bytes" {
  let segs = segments_of("ls.x86_64.macho")
  // __PAGEZERO's filesize is 0, so every address in it must come back as None
  // rather than as an offset that would read unrelated file content.
  match file_offset_of_address(segs, 0x100L) {
    None => ()
    Some(off) => fail("expected None for a zero-fill address, got \{off}")
  }
  // An address past every segment is also None.
  inspect(
    file_offset_of_address(segs, 0x7FFF_FFFF_FFFFL) is None,
    content="true",
  )
}

///|
test "address to offset: the mapping is consistent with segment headers" {
  // For every segment with file bytes, the first byte of the segment maps to
  // fileoff, and the last byte maps to fileoff + filesize - 1.
  let segs = segments_of("ls.x86_64.macho")
  for seg in segs {
    if seg.file_size == 0L {
      continue
    }
    match file_offset_of_address(segs, seg.vmaddr) {
      Some(v) => inspect(v, content=seg.file_offset.to_string())
      None => fail("segment start has no file offset")
    }
    match file_offset_of_address(segs, seg.vmaddr + seg.file_size - 1L) {
      Some(v) =>
        inspect(v, content=(seg.file_offset + seg.file_size - 1L).to_string())
      None => fail("segment end has no file offset")
    }
  }
}

///|
test "reject: a segment claiming more sections than its cmdsize allows" {
  // One LC_SEGMENT_64 whose nsects is large but whose cmdsize is the bare
  // 72-byte header. Reading sections would run into the next structure.
  let buf = Buffer()
  buf.write_uint_le(0xFEED_FACF)
  buf.write_int_le(0x0100_000C)
  buf.write_int_le(0)
  buf.write_uint_le(2)
  buf.write_uint_le(1) // ncmds
  buf.write_uint_le(72) // sizeofcmds: header only, no section table
  buf.write_uint_le(0)
  buf.write_uint_le(0)
  buf.write_uint_le(0x19) // LC_SEGMENT_64
  buf.write_uint_le(72) // cmdsize
  for _ in 0..<16 {
    buf.write_byte(b'\x00') // segname
  }
  buf.write_uint64_le(0) // vmaddr
  buf.write_uint64_le(0) // vmsize
  buf.write_uint64_le(0) // fileoff
  buf.write_uint64_le(0) // filesize
  buf.write_int_le(0) // maxprot
  buf.write_int_le(0) // initprot
  buf.write_uint_le(5) // nsects: five sections...
  buf.write_uint_le(0) // flags; ...but no bytes for them
  let slice = match parse(buf.to_bytes()) {
    Thin(s) => s
    Fat(_) => fail("expected thin")
  }
  try {
    ignore(segments(slice))
    fail("expected a rejection")
  } catch {
    OutOfBounds(what~, ..) => inspect(what, content="section table")
    e => fail("unexpected error: \{e}")
  }
}
