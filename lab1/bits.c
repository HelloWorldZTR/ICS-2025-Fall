/* 
 * CS:APP Data Lab 
 * 
 * <Please put your name and userid here>
 * 
 * bits.c - Source file with your solutions to the Lab.
 *          This is the file you will hand in to your instructor.
 *
 * WARNING: Do not include the <stdio.h> header; it confuses the dlc
 * compiler. You can still use printf for debugging without including
 * <stdio.h>, although you might get a compiler warning. In general,
 * it's not good practice to ignore compiler warnings, but in this
 * case it's OK.  
 */

#if 0
/*
 * Instructions to Students:
 *
 * STEP 1: Read the following instructions carefully.
 */

You will provide your solution to the Data Lab by
editing the collection of functions in this source file.

INTEGER CODING RULES:
 
  Replace the "return" statement in each function with one
  or more lines of C code that implements the function. Your code 
  must conform to the following style:
 
  int Funct(arg1, arg2, ...) {
      /* brief description of how your implementation works */
      int var1 = Expr1;
      ...
      int varM = ExprM;

      varJ = ExprJ;
      ...
      varN = ExprN;
      return ExprR;
  }

  Each "Expr" is an expression using ONLY the following:
  1. Integer constants 0 through 255 (0xFF), inclusive. You are
      not allowed to use big constants such as 0xffffffff.
  2. Function arguments and local variables (no global variables).
  3. Unary integer operations ! ~
  4. Binary integer operations & ^ | + << >>
    
  Some of the problems restrict the set of allowed operators even further.
  Each "Expr" may consist of multiple operators. You are not restricted to
  one operator per line.

  You are expressly forbidden to:
  1. Use any control constructs such as if, do, while, for, switch, etc.
  2. Define or use any macros.
  3. Define any additional functions in this file.
  4. Call any functions.
  5. Use any other operations, such as &&, ||, -, or ?:
  6. Use any form of casting.
  7. Use any data type other than int.  This implies that you
     cannot use arrays, structs, or unions.

 
  You may assume that your machine:
  1. Uses 2s complement, 32-bit representations of integers.
  2. Performs right shifts arithmetically.
  3. Has unpredictable behavior when shifting an integer by more
     than the word size.

EXAMPLES OF ACCEPTABLE CODING STYLE:
  /*
   * pow2plus1 - returns 2^x + 1, where 0 <= x <= 31
   */
  int pow2plus1(int x) {
     /* exploit ability of shifts to compute powers of 2 */
     return (1 << x) + 1;
  }

  /*
   * pow2plus4 - returns 2^x + 4, where 0 <= x <= 31
   */
  int pow2plus4(int x) {
     /* exploit ability of shifts to compute powers of 2 */
     int result = (1 << x);
     result += 4;
     return result;
  }

FLOATING POINT CODING RULES

For the problems that require you to implent floating-point operations,
the coding rules are less strict.  You are allowed to use looping and
conditional control.  You are allowed to use both ints and unsigneds.
You can use arbitrary integer and unsigned constants.

You are expressly forbidden to:
  1. Define or use any macros.
  2. Define any additional functions in this file.
  3. Call any functions.
  4. Use any form of casting.
  5. Use any data type other than int or unsigned.  This means that you
     cannot use arrays, structs, or unions.
  6. Use any floating point data types, operations, or constants.


NOTES:
  1. Use the dlc (data lab checker) compiler (described in the handout) to 
     check the legality of your solutions.
  2. Each function has a maximum number of operators (! ~ & ^ | + << >>)
     that you are allowed to use for your implementation of the function. 
     The max operator count is checked by dlc. Note that '=' is not 
     counted; you may use as many of these as you want without penalty.
  3. Use the btest test harness to check your functions for correctness.
  4. Use the BDD checker to formally verify your functions
  5. The maximum number of ops for each function is given in the
     header comment for each function. If there are any inconsistencies 
     between the maximum ops in the writeup and in this file, consider
     this file the authoritative source.

/*
 * STEP 2: Modify the following functions according the coding rules.
 * 
 *   IMPORTANT. TO AVOID GRADING SURPRISES:
 *   1. Use the dlc compiler to check that your solutions conform
 *      to the coding rules.
 *   2. Use the BDD checker to formally verify that your solutions produce 
 *      the correct answers.
 */


#endif
/* Copyright (C) 1991-2024 Free Software Foundation, Inc.
   This file is part of the GNU C Library.

   The GNU C Library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 2.1 of the License, or (at your option) any later version.

   The GNU C Library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with the GNU C Library; if not, see
   <https://www.gnu.org/licenses/>.  */
/* This header is separate from features.h so that the compiler can
   include it implicitly at the start of every compilation.  It must
   not itself include <features.h> or any other header that includes
   <features.h> because the implicit include comes before any feature
   test macros that may be defined in a source file before it first
   explicitly includes a system header.  GCC knows the name of this
   header in order to preinclude it.  */
/* glibc's intent is to support the IEC 559 math functionality, real
   and complex.  If the GCC (4.9 and later) predefined macros
   specifying compiler intent are available, use them to determine
   whether the overall intent is to support these features; otherwise,
   presume an older compiler has intent to support these features and
   define these macros by default.  */
/* wchar_t uses Unicode 10.0.0.  Version 10.0 of the Unicode Standard is
   synchronized with ISO/IEC 10646:2017, fifth edition, plus
   the following additions from Amendment 1 to the fifth edition:
   - 56 emoji characters
   - 285 hentaigana
   - 3 additional Zanabazar Square characters */

/* 
 * bitOr - x|y using only ~ and & 
 *   Example: bitOr(6, 5) = 7
 *   Legal ops: ~ &
 *   Max ops: 8
 *   Rating: 1
 */
int bitOr(int x, int y) {
  return ~(~x & ~y);
}
/* 
 * upperBits - pads n upper bits with 1's
 *  You may assume 0 <= n <= 32
 *  Example: upperBits(4) = 0xF0000000
 *  Legal ops: ! ~ & ^ | + << >>
 *  Max ops: 10
 *  Rating: 1
 */
int upperBits(int n) {
  int sign = !!n;// 0 -> 0 not 0->1
  return sign << 31 >> (n + ~0); //(n -1)
}
/*
 * fullAdd - 4-bits add using bit-wise operations only.
 *   (0 <= x, y < 16) 
 *   Example: fullAdd(12, 7) = 3,
 *            fullAdd(7, 8) = 15,
 *   Legal ops: ~ | ^ & << >>
 *   Max ops: 30
 *   Rating: 2
 */
int fullAdd(int x, int y) {
    int a = (x ^ y) & 1;
    int ac = (x & y & 1) << 1; // carry 0010
    int b = (x ^ y ^ ac) & 2;
    int bc = (((x & y) | ((x | y) & ac)) & 2) << 1;
    int c = (x ^ y ^ bc) & 4;
    int cc = ((x & y) | ((x | y) & bc) & 4) << 1;
    int d = (x ^ y ^ cc) & 8;
    return a | b | c | d;
}
/* 
 * rotateLeft - Rotate x to the left by n
 *   Can assume that 0 <= n <= 31
 *   Examples: rotateLeft(0x87654321,4) = 0x76543218
 *   Legal ops: ~ & ^ | + << >> !
 *   Max ops: 25
 *   Rating: 3 
 */
int rotateLeft(int x, int n) {
  int nn = 32 + (~n + 1); // 32 - n;

  int hi = x << n;
  int lo = x >> nn;
  int lo_mask = ~(~0 << n);

  return hi | (lo & lo_mask);
}
/*
 * bitParity - returns 1 if x contains an odd number of 0's
 *   Examples: bitParity(5) = 0, bitParity(7) = 1
 *   Legal ops: ! ~ & ^ | + << >>
 *   Max ops: 20
 *   Rating: 4
 */
int bitParity(int x) {
  int ok = x ^ (x>>16);
  ok ^= ok >> 8;
  ok ^= ok >> 4;
  ok ^= ok >> 2;
  ok ^= ok >> 1;
  return (ok & 1); 
}
/* 
 * palindrome - return 1 if x is palindrome in binary form,
 *   return 0 otherwise
 *   A number is palindrome if it is the same when reversed
 *   YOU MAY USE BIG CONST IN THIS PROBLEM, LIKE 0xFFFF0000
 *   YOU MAY USE BIG CONST IN THIS PROBLEM, LIKE 0xFFFF0000
 *   YOU MAY USE BIG CONST IN THIS PROBLEM, LIKE 0xFFFF0000
 *   Example: palindrome(0xff0000ff) = 1,
 *            palindrome(0xff00ff00) = 0
 *   Legal ops: ~ ! | ^ & << >> +
 *   Max ops: 40
 *   Rating: 4

 */
int palindrome(int x) {
  int xx = x;
  xx = ((xx & 0xFFFF0000) >> 16) | ((xx & 0x0000FFFF) << 16);
  xx = ((xx & 0xFF00FF00) >> 8) | ((xx & 0x00FF00FF) << 8);
  xx = ((xx & 0xF0F0F0F0) >> 4) | ((xx & 0x0F0F0F0F) << 4);
  xx = ((xx & 0xCCCCCCCC) >> 2) | ((xx & 0x33333333) << 2);
  xx = ((xx & 0xAAAAAAAA) >> 1) | ((xx & 0x55555555) << 1);
  return !(xx^x);
}
/* 
 * negate - return -x 
 *   Example: negate(1) = -1.
 *   Legal ops: ! ~ & ^ | + << >>
 *   Max ops: 5
 *   Rating: 2
 */
int negate(int x) {
  return ~x + 1;
}
/* 
 * oneMoreThan - return 1 if y is one more than x, and 0 otherwise
 *   Examples oneMoreThan(0, 1) = 1, oneMoreThan(-1, 1) = 0
 *   Legal ops: ~ & ! ^ | + << >>
 *   Max ops: 15
 *   Rating: 2
 */
int oneMoreThan(int x, int y) {
  int eq = (x + 1) ^ y;
  return !(eq | ((~x & y) >> 31)); // is different or x is + and y is -
}
/*
 * ezThreeFourths - multiplies by 3/4 rounding toward 0,
 *   Should exactly duplicate effect of C expression (x*3/4),
 *   including overflow behavior.
 *   Examples: ezThreeFourths(11) = 8
 *             ezThreeFourths(-9) = -6
 *             ezThreeFourths(1073741824) = -268435456 (overflow)
 *   Legal ops: ! ~ & ^ | + << >>
 *   Max ops: 12
 *   Rating: 3
 */
int ezThreeFourths(int x) {
  int fact = (x << 1) + x;
  int sign = fact >> 31 & 1;
  sign = sign | (sign << 1); // create a little mask
  fact += 3 & sign; //equ to if x < 0 add = 3
  fact = fact >> 2;
  return fact;
}
/* 
 * isLess - if x < y  then return 1, else return 0 
 *   Example: isLess(4,5) = 1.
 *   Legal ops: ! ~ & ^ | + << >>
 *   Max ops: 24
 *   Rating: 3
 */
int isLess(int x, int y) {
  int xminy = x + (~y + 1); // x - y
  int sxminy = (xminy >> 31) & 1;
  int sx = x >> 31 & 1;
  int sy = y >> 31 & 1;
  int ovf = (sx ^ sy) & 1; // x and -y is same sign
  ovf &= sx ^ sxminy;

  return (sxminy & !ovf) | (sx & !sy & ovf);
}
/*
 * satMul2 - multiplies by 2, saturating to Tmin or Tmax if overflow
 *   Examples: satMul2(0x30000000) = 0x60000000
 *             satMul2(0x40000000) = 0x7FFFFFFF (saturate to TMax)
 *             satMul2(0x90000000) = 0x80000000 (saturate to TMin)
 *   Legal ops: ! ~ & ^ | + << >>
 *   Max ops: 20
 *   Rating: 3
 */
int satMul2(int x) {
  int mul = x << 1;
  int sign_original = x >> 31;
  int sign_mul = mul >> 31;

  int ovf = (sign_mul ^ sign_original) & 1;
  int ovf_lo = ovf & sign_original;

  int mask = ovf << 31 >> 31; //1111111
  int sign;

  mask = mask ^ (ovf << 31); //0111111

  mul = mul & ~(1<<31); // no sign
  
  sign = (sign_original & !ovf) << 31; // the sign bit in the result if no ovf

  return ((mul | mask) + ovf_lo) | sign; // if lower ovf add 1 to make 0x80000000
}
/*
 * modThree - calculate x mod 3 without using %.
 *   Example: modThree(12) = 0,
 *            modThree(2147483647) = 1,
 *            modThree(-8) = -2,
 *   Legal ops: ~ ! | ^ & << >> +
 *   Max ops: 60
 *   Rating: 4
 */
int modThree(int x) {
  int sgnx = x >> 31; // 11111 or 0
  int b0, b1, b2 ,b3;
  int mask;
  int is3;

  x = (x ^ sgnx) + (sgnx & 1); // abs(x)

  b0 = x & 0xFF;
  b1 = (x >> 8) & 0xFF;
  b2 = (x >> 16) & 0xFF;
  b3 = (x >> 24) & 0xFF;
  x = b0 + b1 + b2 + b3; // max FF << 2, safely with in 12 bits

  b0 = x & 0xF;
  b1 = (x >> 4) & 0xF;
  b2 = (x >> 8) & 0xF;
  x = b0 + b1 + b2;

  x = (x >> 2) + (x & 3); // keep mod 3
  x = (x >> 2) + (x & 3);
  x = (x >> 2) + (x & 3);

  is3 = !(x ^ 3);
  mask = ~is3 + 1; // if is3 mask = 1111 else 0000
  x = (x & ~mask); // if is3 x = 0

  x = (x ^ sgnx) + (sgnx & 1); // restore sign
  return x;
}
/* 
 * float_half - Return bit-level equivalent of expression 0.5*f for
 *   floating point argument f.
 *   Both the argument and result are passed as unsigned int's, but
 *   they are to be interpreted as the bit-level representation of
 *   single-precision floating point values.
 *   When argument is NaN, return argument
 *   Legal ops: Any integer/unsigned operations incl. ||, &&. also if, while
 *   Max ops: 30
 *   Rating: 4
 */
unsigned float_half(unsigned uf) {
  int exp = (uf >> 23) & 0xFF;
  int frac = uf & 0x7FFFFF; // lower 23
  int sgn = uf & (1 << 31);

  if (!(exp ^ 0xFF)) { // exp 11111111
    return uf;
  }
  if (exp == 1) { // normalized -> denormalized
    frac = frac | (1 << 23); // add a 1 in front of all frac
    exp = 0;
  }
  if (!exp) { // denorm 
    int add = (frac & 3) == 3;
    frac = (frac >> 1) + add;
    return sgn | frac; // no exp
  }

  return sgn | ((exp - 1) << 23) | frac;
}
/* 
 * float_i2f - Return bit-level equivalent of expression (float) x
 *   Result is returned as unsigned int, but
 *   it is to be interpreted as the bit-level representation of a
 *   single-precision floating point values.
 *   Legal ops: Any integer/unsigned operations incl. ||, &&. also if, while
 *   Max ops: 30
 *   Rating: 4
 */
unsigned float_i2f(int x) {
    unsigned sign = x >> 31 & 1;
    unsigned ux = x;
    unsigned frac;
    unsigned remainder;
    int exp = 0;

    // special cases
    if (x == 0) return 0;
    if (sign) ux = ~x + 1;

    while (!(ux & 0x80000000)) { // first hi 1
        ux <<= 1;
        exp++;
    }
    ux <<= 1; // no hi 1
    exp = 127 + (31 - exp);
    frac = ux >> 9; //trunc 23
    // rounding
    remainder = ux & 0x1FF;
    if (remainder > 0x100 || (remainder == 0x100 && (frac & 1))) {
        frac += 1;
        if (frac >> 23) {
            frac &= 0x7FFFFF;
            exp += 1;
        }
    }
    return (sign << 31) | (exp << 23) | frac;
}
/* 
 * float64_f2i - Return bit-level equivalent of expression (int) f
 *   for 64 bit floating point argument f.
 *   Argument is passed as two unsigned int, but
 *   it is to be interpreted as the bit-level representation of a
 *   double-precision floating point value.
 *   Notice: uf1 contains the lower part of the f64 f
 *   Anything out of range (including NaN and infinity) should return
 *   0x80000000u.
 *   Legal ops: Any integer/unsigned operations incl. ||, &&. also if, while
 *   Max ops: 20
 *   Rating: 4
 */
int float64_f2i(unsigned uf1, unsigned uf2) {
  int sgn = uf2 & (1 << 31);
  int exp = (uf2 >> 20) & 0x7FF; // this is double!
  unsigned frac;
  int E = exp - 1023;
  // printf("exp: %d\n", E);
  if(E<0) return 0;
  if(E>=31) return (1<<31);

  frac = uf2 << 12 | uf1 >> 20; // discard lower bits
  frac = (frac >> 1) | (1 << 31); // add hi 1
  frac = frac >> (31 - E);

  if (sgn) frac = ~frac + 1;
  return frac;
}
/* 
 * float_pwr2 - Return bit-level equivalent of the expression 2.0^x
 *   (2.0 raised to the power x) for any 32-bit integer x.
 *
 *   The unsigned value that is returned should have the identical bit
 *   representation as the single-precision floating-point number 2.0^x.
 *   If the result is too small to be represented as a denorm, return
 *   0. If too large, return +INF.
 * 
 *   Legal ops: Any integer/unsigned operations incl. ||, &&. Also if, while 
 *   Max ops: 30 
 *   Rating: 4
 */
unsigned float_pwr2(int x) {
    // 1 + 8 + 23
    // denorm min 2^-149 (2^-23)*2^-126
    // denorm max 2^-127 (2^-1)*2^-126
    // norm min 2^-126 1*2^-126
    // norm max 2^127 1*2^127
    unsigned frac;
    int shift;

    if (x < -149) return 0;
    if (x >= 128) return 0x7F800000;
    if (x >= -126) { // norm is ok
        return (x + 127) << 23;
    } // denorm
    frac = 1 << (149 + x);
    return frac;
}

