// Source for `sample.classic`, the fixture that uses the pre-chained fixup
// encoding.
//
// Every other binary here is linked with chained fixups, where each slot
// describes itself. Before that, an image described its relocations with two
// opcode streams named by `LC_DYLD_INFO_ONLY`, and x86_64 slices of universal
// binaries still use them: `ls`, `cp`, `mv` and 68 others in `/usr/bin` carry
// no `LC_DYLD_CHAINED_FIXUPS` at all.
//
// A parser that only knows the chained form reports those files as having no
// fixups, which is a different and wrong answer from "this encoding is not
// read". That is what `sample.classic` guards against.
//
// The array of string literals gives the rebase stream something to relocate,
// and `printf` gives the bind stream an import, so both streams are non-empty
// and both are exercised.

#include <stdio.h>

static const char *names[] = {
  "alpha",
  "beta",
  "gamma",
};

static int counter = 7;

int main(void) {
  for (int i = 0; i < 3; i++) {
    printf("%s %d\n", names[i], counter + i);
  }
  return 0;
}