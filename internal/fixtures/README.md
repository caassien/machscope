# Test fixtures

These are unmodified Apple system binaries, used as parser inputs so that the
tests exercise bytes a real linker produced rather than bytes the test author
believed a linker would produce.

| File | Origin |
|---|---|
| `ls.fat.macho` | `/bin/ls` from macOS 15, a universal binary with x86_64 and arm64e slices |
| `ls.x86_64.macho` | the x86_64 slice, extracted with `lipo -thin x86_64` |
| `ls.arm64e.macho` | the arm64e slice, extracted with `lipo -thin arm64e` |

They are inputs only: `machscope` neither links against them nor ships any part
of them in its own output. They are Apple's binaries, redistributed here solely
so that `moon test` can run anywhere without a macOS machine present.

Expected values in `oracle_wbtest.mbt` were taken from `otool -h` and
`otool -f` on these same files:

```
$ otool -h internal/fixtures/ls.arm64e.macho
      magic  cputype cpusubtype  caps    filetype ncmds sizeofcmds      flags
 0xfeedfacf 16777228          2  0x80           2    20       1712 0x00200085
```