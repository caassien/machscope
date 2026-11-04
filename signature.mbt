// The embedded code signature: the superblob index and the code directory.
//
// `LC_CODE_SIGNATURE` names a byte range that holds a `SuperBlob`: a count,
// then an index of (type, offset) pairs, then the blobs themselves. The two
// blobs worth decoding without a full CMS implementation are the CodeDirectory,
// which says what was signed and how, and the entitlements, which say what the
// process is allowed to do.

///|
/// `LC_CODE_SIGNATURE`.
pub const LC_CODE_SIGNATURE : UInt32 = 0x1D

///|
/// Magic of the outer `SuperBlob`.
pub const CSMAGIC_EMBEDDED_SIGNATURE : UInt32 = 0xFADE_0CC0

///|
/// Magic of a CodeDirectory blob.
pub const CSMAGIC_CODEDIRECTORY : UInt32 = 0xFADE_0C02

///|
/// The `CSSLOT_ENTITLEMENTS` index type: a DER-encoded entitlement plist.
///
/// The value is 5, but Apple's embedded signatures use slot 0x10000 for it; the
/// two are distinct constants in `<Security/SecCode.h>` and only the latter
/// appears in binaries produced by the current toolchain.
pub const CSSLOT_ENTITLEMENTS : UInt32 = 0x0001_0000

///|
/// Where the signature lives inside the file.
pub(all) struct SignatureRegion {
  /// `dataoff`: absolute offset of the SuperBlob.
  offset : Int64
  /// `datasize`: its byte length.
  size : Int64
}

///|
/// One entry of the SuperBlob index.
pub(all) struct SignatureBlobRef {
  /// `CSSLOT_*` type number.
  slot : UInt32
  /// Offset of the blob from the start of the SuperBlob.
  offset : Int64
  /// Blob magic, read from the blob header.
  magic : UInt32
  /// Blob length, read from the blob header.
  length : Int64
}

///|
/// A decoded `CodeDirectory`.
///
/// Only the fields that identify the signature are decoded: the version tells a
/// reader how far the structure extends, and hashing the rest would require
/// re-deriving every page hash, which is a verification concern rather than an
/// inspection one.
pub(all) struct CodeDirectory {
  /// `CSMAGIC_CODEDIRECTORY`.
  magic : UInt32
  /// Byte length of the directory.
  length : Int64
  /// Structure version, e.g. `0x20400`.
  version : UInt32
  /// `CD_*` flag bits.
  flags : UInt32
  /// Signing identifier, usually a reverse-DNS bundle id.
  identifier : String
  /// `teamID`, present from version `0x20200`.
  team_id : String
  /// `hashType`: 1 SHA-1, 2 SHA-256.
  hash_type : UInt32
  /// `hashSize`: bytes per hash, 20 for SHA-1 and 32 for SHA-256.
  hash_size : UInt32
  /// `pageSize`: log2 of the page size the hashes cover, or 0 for one hash.
  page_size : UInt32
  /// `nCodeSlots`: number of page hashes.
  code_slots : UInt32
}

///|
/// Finds the `LC_CODE_SIGNATURE` command in a slice.
pub fn signature_region(
  slice : MachSlice,
) -> SignatureRegion? raise MachscopeError {
  for cmd in slice.commands {
    if cmd.cmd != LC_CODE_SIGNATURE {
      continue
    }
    let body = command_payload(slice, cmd)
    let cur = Cursor::{ pos: body.start, endian: slice.header.kind.endian(), }
    let (dataoff, cur) = body.read_u32(cur)
    let (datasize, _) = body.read_u32(cur)
    let region = SignatureRegion::{
      offset: dataoff.to_int64(),
      size: datasize.to_int64(),
    }
    slice.bounds.require(region.offset, region.size, "code signature")
    return Some(region)
  }
  None
}

///|
/// Reads the SuperBlob index of a signature region.
///
/// Every blob's own header is read here so that a caller can inspect the index
/// without decoding blobs it does not need, and so that a blob pointing outside
/// the region is reported before anything tries to parse it.
pub fn signature_blobs(
  slice : MachSlice,
  region : SignatureRegion,
) -> Array[SignatureBlobRef] raise MachscopeError {
  let endian = Endian::Big // code signing structures are always big-endian
  let b = slice.bounds
  let cur = Cursor::{ pos: region.offset, endian, }
  let (magic, cur) = b.read_u32(cur)
  if magic != CSMAGIC_EMBEDDED_SIGNATURE {
    raise BadMagic(magic~)
  }
  let (length, cur) = b.read_u32(cur)
  let (count, cur) = b.read_u32(cur)
  if length.to_int64() > region.size {
    raise Inconsistent(
      what="SuperBlob",
      detail="declared length exceeds the signature region",
    )
  }
  b.require(cur.pos, count.to_int64() * 8L, "signature blob index")
  let refs : Array[SignatureBlobRef] = []
  let mut at = cur.pos
  for _ in 0..<count.reinterpret_as_int() {
    let c = Cursor::{ pos: at, endian, }
    let (slot, c) = b.read_u32(c)
    let (offset, _) = b.read_u32(c)
    let blob_at = region.offset + offset.to_int64()
    if blob_at + 8L > region.offset + length.to_int64() {
      raise OutOfBounds(
        what="signature blob",
        offset=blob_at,
        size=8L,
        limit=region.offset + length.to_int64(),
      )
    }
    let bc = Cursor::{ pos: blob_at, endian, }
    let (blob_magic, bc) = b.read_u32(bc)
    let (blob_len, _) = b.read_u32(bc)
    refs.push(SignatureBlobRef::{
      slot,
      offset: offset.to_int64(),
      magic: blob_magic,
      length: blob_len.to_int64(),
    })
    at = at + 8L
  }
  refs
}

///|
/// Decodes the `CodeDirectory` blob from the index.
pub fn code_directory(
  slice : MachSlice,
  region : SignatureRegion,
) -> CodeDirectory? raise MachscopeError {
  let refs = signature_blobs(slice, region)
  let mut dir : CodeDirectory? = None
  for r in refs {
    if r.magic != CSMAGIC_CODEDIRECTORY {
      continue
    }
    dir = Some(decode_code_directory(slice, region, r))
  }
  dir
}

///|
/// Reads the fixed `CodeDirectory` fields that this library exposes.
fn decode_code_directory(
  slice : MachSlice,
  region : SignatureRegion,
  entry : SignatureBlobRef,
) -> CodeDirectory raise MachscopeError {
  let b = slice.bounds
  let base = region.offset + entry.offset
  let endian = Endian::Big
  let c = Cursor::{ pos: base, endian, }
  let (magic, c) = b.read_u32(c)
  let (length, c) = b.read_u32(c)
  let (version, c) = b.read_u32(c)
  let (flags, c) = b.read_u32(c)
  let (hash_offset, c) = b.read_u32(c)
  let (identifier_offset, _) = b.read_u32(c)
  // The identifier is an offset from the start of the blob.
  let identifier = b.fixed_name(
    base + identifier_offset.to_int64(),
    256L,
    "code directory identifier",
  )
  // Offsets below are relative to the blob start, per
  // `<Security/SecCode.h>`. Note that nSpecialSlots is a 32-bit word, not a
  // byte: it is followed by nCodeSlots, codeLimit, then four single-byte
  // fields.
  let (slots_at, _) = b.read_u32(Cursor::{ pos: base + 24L, endian, })
  let (code_slots, code_limit) = b.read_u32(Cursor::{ pos: base + 28L, endian, })
  let (hash_size, after_size) = b.read_u8(Cursor::{ pos: base + 36L, endian, })
  let (hash_type, after_type) = b.read_u8(after_size)
  let (_, after_platform) = b.read_u8(after_type)
  let (page_size, _) = b.read_u8(after_platform)
  let _ = (slots_at, code_limit)
  // teamID is a separate offset field, present from version 0x20200.
  let mut team_id = ""
  if version >= 0x0002_0200U {
    let team_offset_at = base + 48L
    let (team_offset, _) = b.read_u32(Cursor::{ pos: team_offset_at, endian, })
    if team_offset != 0U {
      team_id = b.fixed_name(
        base + team_offset.to_int64(),
        256L,
        "code directory team id",
      )
    }
  }
  // `hash_offset` must point inside the blob; checking it here means the page
  // hashes are known to be addressable even though this version does not read
  // them.
  if hash_offset.to_int64() > entry.length {
    raise Inconsistent(
      what="CodeDirectory",
      detail="hash offset outside the directory",
    )
  }
  CodeDirectory::{
    magic,
    length: length.to_int64(),
    version,
    flags,
    identifier,
    team_id,
    hash_type,
    hash_size,
    page_size,
    code_slots,
  }
}

///|
/// Extracts the entitlements plist from a signature, if there is one.
///
/// The payload is DER-wrapped: a PKCS#7 `SignedData` whose entitlement
/// attribute holds the property list. The returned bytes are the plist itself,
/// not yet parsed.
pub fn entitlements_der(
  slice : MachSlice,
  region : SignatureRegion,
) -> Bytes? raise MachscopeError {
  let refs = signature_blobs(slice, region)
  let mut payload : Bytes? = None
  for r in refs {
    if r.slot != CSSLOT_ENTITLEMENTS {
      continue
    }
    let base = region.offset + r.offset
    // A blob is a magic, a length, then the payload.
    let blob = slice.bounds.slice(base + 8L, r.length - 8L, "entitlements blob")
    payload = Some(entitlements_from_blob(blob))
  }
  payload
}

///|
/// Walks a PKCS#7 blob down to the octet string holding the plist.
///
/// The layout is `ContentInfo > SignedData > [0] > encapContentInfo > [0] >
/// OCTET STRING`. Each level is checked rather than indexed blindly, because a
/// signature produced by a different tool may omit optional wrappers.
fn entitlements_from_blob(blob : Bytes) -> Bytes raise MachscopeError {
  let top = read_element(blob, 0L, blob.length().to_int64())
  let mut found : Bytes? = None
  let stack : Array[DerElement] = [top]
  for _ in 0..<24 {
    if stack.is_empty() || found is Some(_) {
      break
    }
    let el = stack.pop().unwrap()
    if el.tag == TAG_OCTET_STRING {
      found = Some(octet_string(blob, el))
    } else {
      let constructed = el.tag == TAG_SEQUENCE ||
        el.tag == TAG_SET ||
        el.tag == TAG_CTX_0 ||
        el.tag == TAG_CTX_1
      if constructed {
        for child in children(blob, el) {
          stack.push(child)
        }
      }
    }
  }
  match found {
    Some(bytes) => bytes
    None =>
      raise Inconsistent(
        what="entitlements blob",
        detail="no octet string holding a plist",
      )
  }
}
