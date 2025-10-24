#include <iostream>
#include <limits.h>

using namespace std;

void printbits(int x) {
    for(int i=31; i>=0; i--) {
        printf("%d", x>>i & 1);
    }
    printf("\n");
}

void print(char* name, int x) {
    printf("%s: ", name);
    printbits(x);
}

int fullAdd(int x, int y) {
    print("x ", x);
    print("y ", y);
    int a = (x ^ y) & 1;
    int ac = (x & y & 1) << 1; // carry 0010
    int b = (x ^ y ^ ac) & 2;
    int bc = (((x & y) | ((x | y) & ac)) & 2) << 1;
    int c = (x ^ y ^ bc) & 4;
    int cc = ((x & y) | ((x | y) & bc) & 4) << 1;
    int d = (x ^ y ^ cc) & 8;
    print("ac", ac);
    print("bc", bc);
    print("cc", cc);
    print("a ", a);
    print("b ", b);
    print("c ", c);
    print("d ", d);
    
    return a | b | c | d;
}


int rotateLeft(int x, int n) {
    int nn = 32 + (~n + 1); // 32 - n;

    int hi = x << n;
    int lo = x >> nn;
    int lo_mask = ~(~0 << n);

    print("x ", x);
    print("hi", hi);
    print("lo", lo);
    print("ms", lo_mask);

    return hi | (lo & lo_mask);
}

int oneMoreThan(int x, int y) {
  int eq = (x + 1) ^ y;

  eq |= eq >> 16;
  eq |= eq >> 8;
  eq |= eq >> 4;
  eq |= eq >> 2;
  eq |= eq >> 1;
  
  return !((eq & 1) | ((~x & y) >> 31));
}

int satMul2(int x) {
  int mul = x << 1;
  int sign_original = x >> 31;
  int sign_mul = mul >> 31;

  int ovf = (sign_mul ^ sign_original);
  int ovf_hi = ovf & sign_mul;
  int ovf_lo = ovf & sign_original;

  int mask = ovf << 31 >> 31; //1111111
  mask = mask ^ (ovf << 31); //0111111

  mul = mul & ~(1<<31); // no sign
  int sign = sign_original & !ovf;
  sign = sign << 31;

    print("mask", mask);
    print("ovf ", ovf);
    print("ovf_hi", ovf_hi);
    print("ovf_lo", ovf_lo);



  return ((mul | mask) + ovf_lo) | sign;
}

int float64_f2i(unsigned uf1, unsigned uf2) {
  int sgn = uf2 & (1 << 31);
  int exp = (uf2 >> 20) & 0x7FF; // this is double!
  unsigned frac;
  int E = exp - 1023;
  printf("exp: %d\n", E);
  if(E<0) return 0;
  if(E>=31) return (1<<31);

  frac = uf2 << 12 | uf1 >> 20; // discard lower bits
  frac = (frac >> 1) | (1 << 31); // add hi 1
  frac = frac >> (31 - E);

  if (sgn) frac = ~frac + 1;
  return frac;
}

int main() {
 int ret = float64_f2i(2147483648, 1105199104);
 print("ret", ret);
}