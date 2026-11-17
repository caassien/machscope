// Source for `sample.chains`, the fixture with a long chained-fixup run.
//
// Every `sample.*` fixture built from `sample.c` carries exactly one fixup: one
// import in `__got`. One fixup is enough to pin down what a slot decodes to, but
// it cannot tell a chain walk that follows the whole chain from one that stops
// after the first slot — and a walk that stopped early is exactly the bug that
// `next` being read from the low bits of `target` produced, which every
// single-slot fixture still passed.
//
// The rebases below are what fixes that. Sixty-four `static` pointers into
// string literals get relocated at load time, and ld64 packs them into one
// `__DATA,__data` run with consecutive `next` values, so the walk has to follow
// 64 links inside a single page to reach them all. The `printf` call adds the
// one bind, so both kinds of edge are present in this fixture.
//
// The strings are distinguishable at offset 6 (`"%s"` here prints the digit) so
// a human can tell the rebases apart in `dyld_info -fixups`; nothing in the
// tests depends on that. `-O0` keeps every pointer in memory rather than letting
// the optimiser fold the loads away, which would empty out the section.

#include <stdio.h>

static const char *p0 = "value 0";
static const char *p1 = "value 1";
static const char *p2 = "value 2";
static const char *p3 = "value 3";
static const char *p4 = "value 4";
static const char *p5 = "value 5";
static const char *p6 = "value 6";
static const char *p7 = "value 7";
static const char *p8 = "value 8";
static const char *p9 = "value 9";
static const char *p10 = "value 10";
static const char *p11 = "value 11";
static const char *p12 = "value 12";
static const char *p13 = "value 13";
static const char *p14 = "value 14";
static const char *p15 = "value 15";
static const char *p16 = "value 16";
static const char *p17 = "value 17";
static const char *p18 = "value 18";
static const char *p19 = "value 19";
static const char *p20 = "value 20";
static const char *p21 = "value 21";
static const char *p22 = "value 22";
static const char *p23 = "value 23";
static const char *p24 = "value 24";
static const char *p25 = "value 25";
static const char *p26 = "value 26";
static const char *p27 = "value 27";
static const char *p28 = "value 28";
static const char *p29 = "value 29";
static const char *p30 = "value 30";
static const char *p31 = "value 31";
static const char *p32 = "value 32";
static const char *p33 = "value 33";
static const char *p34 = "value 34";
static const char *p35 = "value 35";
static const char *p36 = "value 36";
static const char *p37 = "value 37";
static const char *p38 = "value 38";
static const char *p39 = "value 39";
static const char *p40 = "value 40";
static const char *p41 = "value 41";
static const char *p42 = "value 42";
static const char *p43 = "value 43";
static const char *p44 = "value 44";
static const char *p45 = "value 45";
static const char *p46 = "value 46";
static const char *p47 = "value 47";
static const char *p48 = "value 48";
static const char *p49 = "value 49";
static const char *p50 = "value 50";
static const char *p51 = "value 51";
static const char *p52 = "value 52";
static const char *p53 = "value 53";
static const char *p54 = "value 54";
static const char *p55 = "value 55";
static const char *p56 = "value 56";
static const char *p57 = "value 57";
static const char *p58 = "value 58";
static const char *p59 = "value 59";
static const char *p60 = "value 60";
static const char *p61 = "value 61";
static const char *p62 = "value 62";
static const char *p63 = "value 63";

int main(void) {
  long total = 0;
  total += (long)p0[6];
  total += (long)p1[6];
  total += (long)p2[6];
  total += (long)p3[6];
  total += (long)p4[6];
  total += (long)p5[6];
  total += (long)p6[6];
  total += (long)p7[6];
  total += (long)p8[6];
  total += (long)p9[6];
  total += (long)p10[6];
  total += (long)p11[6];
  total += (long)p12[6];
  total += (long)p13[6];
  total += (long)p14[6];
  total += (long)p15[6];
  total += (long)p16[6];
  total += (long)p17[6];
  total += (long)p18[6];
  total += (long)p19[6];
  total += (long)p20[6];
  total += (long)p21[6];
  total += (long)p22[6];
  total += (long)p23[6];
  total += (long)p24[6];
  total += (long)p25[6];
  total += (long)p26[6];
  total += (long)p27[6];
  total += (long)p28[6];
  total += (long)p29[6];
  total += (long)p30[6];
  total += (long)p31[6];
  total += (long)p32[6];
  total += (long)p33[6];
  total += (long)p34[6];
  total += (long)p35[6];
  total += (long)p36[6];
  total += (long)p37[6];
  total += (long)p38[6];
  total += (long)p39[6];
  total += (long)p40[6];
  total += (long)p41[6];
  total += (long)p42[6];
  total += (long)p43[6];
  total += (long)p44[6];
  total += (long)p45[6];
  total += (long)p46[6];
  total += (long)p47[6];
  total += (long)p48[6];
  total += (long)p49[6];
  total += (long)p50[6];
  total += (long)p51[6];
  total += (long)p52[6];
  total += (long)p53[6];
  total += (long)p54[6];
  total += (long)p55[6];
  total += (long)p56[6];
  total += (long)p57[6];
  total += (long)p58[6];
  total += (long)p59[6];
  total += (long)p60[6];
  total += (long)p61[6];
  total += (long)p62[6];
  total += (long)p63[6];
  printf("%ld\n", total);
  return 0;
}