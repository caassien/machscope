// JSON output.
//
// The CLI needs a machine-readable form so it can sit in a build script or feed
// another tool. Building `Json` values in the library rather than formatting
// strings in the CLI keeps the CLI free of schema knowledge and lets a caller
// re-serialize the report however it likes.

///|
/// The header of one architecture as a JSON object.
pub fn MachHeader::to_json(self : MachHeader) -> Json {
  let fields : Map[String, Json] = Map([])
  fields["magic"] = Json::string(Show::to_string(self.kind))
  fields["endian"] = Json::string(Show::to_string(self.kind.endian()))
  fields["pointer_size"] = Json::number(self.kind.pointer_size().to_double())
  fields["cpu_type"] = Json::number(self.cpu_type.to_double())
  fields["cpu_subtype"] = Json::number(self.cpu_subtype_base().to_double())
  fields["cpu_capabilities"] = Json::number(self.cpu_capabilities().to_double())
  fields["file_type"] = Json::number(self.file_type.to_int64().to_double())
  fields["ncmds"] = Json::number(self.ncmds.to_int64().to_double())
  fields["sizeofcmds"] = Json::number(self.sizeofcmds.to_int64().to_double())
  fields["flags"] = Json::number(self.flags.to_int64().to_double())
  Json::object(fields)
}

///|
/// One segment and its sections as a JSON object.
pub fn Segment::to_json(self : Segment) -> Json {
  let sections : Array[Json] = []
  for s in self.sections {
    let f : Map[String, Json] = Map([])
    f["name"] = Json::string(s.name)
    f["addr"] = Json::string("0x\{hex(s.addr)}")
    f["size"] = Json::number(s.size.to_double())
    f["file_offset"] = Json::number(s.file_offset.to_int64().to_double())
    f["align"] = Json::number(s.align.to_int64().to_double())
    f["flags"] = Json::string("0x\{hex(s.flags.to_int64())}")
    f["zero_fill"] = Json::boolean(s.is_zero_fill())
    f["debug"] = Json::boolean(s.is_debug())
    sections.push(Json::object(f))
  }
  let fields : Map[String, Json] = Map([])
  fields["name"] = Json::string(self.name)
  fields["vmaddr"] = Json::string("0x\{hex(self.vmaddr)}")
  fields["vmsize"] = Json::number(self.vmsize.to_double())
  fields["file_offset"] = Json::number(self.file_offset.to_double())
  fields["file_size"] = Json::number(self.file_size.to_double())
  fields["init_prot"] = Json::number(self.init_prot.to_int64().to_double())
  fields["flags"] = Json::number(self.flags.to_int64().to_double())
  fields["sections"] = Json::array(sections)
  Json::object(fields)
}

///|
/// One symbol as a JSON object.
pub fn Symbol::to_json(self : Symbol) -> Json {
  let fields : Map[String, Json] = Map([])
  fields["name"] = Json::string(self.name)
  fields["address"] = Json::string("0x\{hex(self.n_value)}")
  fields["type"] = Json::number(self.n_type.to_int64().to_double())
  fields["sect"] = Json::number(self.n_sect.to_int64().to_double())
  fields["desc"] = Json::number(self.n_desc.to_int64().to_double())
  fields["external"] = Json::boolean(self.is_external())
  fields["debug"] = Json::boolean(self.is_debug())
  Json::object(fields)
}

///|
/// One export as a JSON object.
pub fn Export::to_json(self : Export) -> Json {
  let fields : Map[String, Json] = Map([])
  fields["name"] = Json::string(self.name)
  fields["offset"] = Json::string(
    "0x\{hex(self.address.reinterpret_as_int64())}",
  )
  fields["flags"] = Json::number(self.flags.reinterpret_as_int64().to_double())
  fields["weak"] = Json::boolean(self.is_weak())
  fields["reexport"] = Json::boolean(self.is_reexport())
  if self.original_name != "" {
    fields["original_name"] = Json::string(self.original_name)
  }
  Json::object(fields)
}

///|
/// A resolved source position as a JSON object.
pub fn SourceLocation::to_json(self : SourceLocation) -> Json {
  let fields : Map[String, Json] = Map([])
  fields["file"] = Json::string(self.file)
  fields["line"] = Json::number(self.line.to_int64().to_double())
  fields["column"] = Json::number(self.column.to_int64().to_double())
  Json::object(fields)
}

///|
/// Builds a report for one architecture.
///
/// Sections are omitted when not requested so that a caller asking only for the
/// header does not pay for a full table walk, and so that a failure in one
/// section does not take down the whole report.
pub fn slice_report(
  slice : MachSlice,
  segments_~ : Bool = false,
  symbols_~ : Bool = false,
  exports_~ : Bool = false,
) -> Json raise MachscopeError {
  let fields : Map[String, Json] = Map([])
  fields["header"] = slice.header.to_json()
  let commands : Array[Json] = []
  for cmd in slice.commands {
    let f : Map[String, Json] = Map([])
    f["cmd"] = Json::string("0x\{hex(cmd.cmd.to_int64())}")
    f["size"] = Json::number(cmd.size.to_int64().to_double())
    f["offset"] = Json::number(cmd.offset.to_double())
    commands.push(Json::object(f))
  }
  fields["commands"] = Json::array(commands)
  if segments_ {
    let segs : Array[Json] = []
    for seg in segments(slice) {
      segs.push(seg.to_json())
    }
    fields["segments"] = Json::array(segs)
  }
  if symbols_ {
    let syms : Array[Json] = []
    for s in symbols(slice) {
      syms.push(s.to_json())
    }
    fields["symbols"] = Json::array(syms)
  }
  if exports_ {
    let exps : Array[Json] = []
    for e in exports(slice) {
      exps.push(e.to_json())
    }
    fields["exports"] = Json::array(exps)
  }
  Json::object(fields)
}

///|
/// Builds a report for a whole file.
///
/// A thin image reports `architectures` with one entry; a fat one reports each
/// slice. The shape is the same either way so that a consumer does not have to
/// branch on which kind of file it was given.
pub fn file_report(
  file : MachFile,
  segments_~ : Bool = false,
  symbols_~ : Bool = false,
  exports_~ : Bool = false,
) -> Json raise MachscopeError {
  let archs : Array[Json] = []
  match file {
    Thin(slice) =>
      archs.push(slice_report(slice, segments_~, symbols_~, exports_~))
    Fat(slices) =>
      for s in slices {
        // The slice's own placement in the file is merged into the same object
        // as its image, so that a consumer reads `architectures[i].header` and
        // `architectures[i].symbols` whichever kind of file it was given.
        let inner = slice_report(s.image, segments_~, symbols_~, exports_~)
        let fields : Map[String, Json] = match inner {
          Object(m) => m
          _ => Map([])
        }
        fields["fat_cpu_type"] = Json::number(s.cpu_type.to_double())
        fields["fat_cpu_subtype"] = Json::number(
          s.cpu_subtype_base().to_double(),
        )
        fields["fat_offset"] = Json::number(s.offset.to_double())
        fields["fat_size"] = Json::number(s.size.to_double())
        fields["fat_align"] = Json::number(s.align.to_int64().to_double())
        archs.push(Json::object(fields))
      }
  }
  let fields : Map[String, Json] = Map([])
  fields["architectures"] = Json::array(archs)
  Json::object(fields)
}
