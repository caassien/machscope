// Source for `sample.weak`, the fixture with a weak definition in its export
// trie.
//
// The export trie stores per-symbol flags, and `EXPORT_SYMBOL_FLAGS_WEAK_DEFINITION`
// is one of them: a weak definition can be replaced by a strong one in another
// image at link time. `dyld_info -exports` marks such a symbol `[weak-def]`.
//
// Without this fixture the flag was untested. Flipping the constant it is read
// with left every test passing, because every export in every other fixture is
// a plain strong definition — the branch that reads the bit was never entered
// with a set bit.
//
// One weak function and one ordinary function, so a test can assert that the
// flag is read per symbol rather than for the whole trie.

__attribute__((weak)) int weak_thing(void) {
  return 1;
}

int normal_thing(void) {
  return 2;
}

int main(void) {
  return weak_thing() + normal_thing();
}