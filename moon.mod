// Learn more about moon.mod configuration:
// https://docs.moonbitlang.com/en/latest/toolchain/moon/module.html
//
// To add a dependency, run this command in your terminal:
//   moon add moonbitlang/x
//
// Or manually declare it in `import`, for example:
// import {
//   "moonbitlang/x@0.4.6",
// }

name = "caassien/machscope"

version = "0.2.0"

readme = "README.mbt.md"

repository = "https://github.com/caassien/machscope"

license = "Apache-2.0"

keywords = [ "macho", "dwarf", "binary-analysis", "dsym", "apple" ]

preferred_target = "wasm"

description = "Mach-O and DWARF inspection in pure MoonBit: segments, symbols, code signature entitlements and crash-address symbolication, with no Apple toolchain required."

import {
  "moonbitlang/x@0.5.7",
}
