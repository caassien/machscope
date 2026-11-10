#include <stdio.h>

// A two-function program, compiled by make_fixtures.sh into the binaries and
// the dSYM the tests read. `helper` is not inlined away at -O0, so the export
// trie and the line table both have something to describe.

static int helper(int x) { return x * 2; }

int compute(int n) {
  int total = 0;
  for (int i = 0; i < n; i++) {
    total += helper(i);
  }
  return total;
}

int main(void) {
  printf("%d\n", compute(21));
  return 0;
}
