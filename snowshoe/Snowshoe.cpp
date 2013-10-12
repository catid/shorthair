/*
	Copyright (c) 2013 Christopher A. Taylor.  All rights reserved.

	Redistribution and use in source and binary forms, with or without
	modification, are permitted provided that the following conditions are met:

	* Redistributions of source code must retain the above copyright notice,
	  this list of conditions and the following disclaimer.
	* Redistributions in binary form must reproduce the above copyright notice,
	  this list of conditions and the following disclaimer in the documentation
	  and/or other materials provided with the distribution.
	* Neither the name of Tabby nor the names of its contributors may be
	  used to endorse or promote products derived from this software without
	  specific prior written permission.

	THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
	AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
	IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
	ARE DISCLAIMED.  IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
	LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
	CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
	SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
	INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
	CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
	ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
	POSSIBILITY OF SUCH DAMAGE.
*/

#include "Platform.hpp"
using namespace cat;

/*
 * "Simplicity is the ultimate sophistication." -Leonardo da Vinci
 *
 * Elliptic Curve Cryptography:
 *
 * Supported operations:
 * + Fixed Base Point Multiplication (keygen)
 * + Variable Base Point Multiplication (DH)
 * + Simultaneous Point Multiplication (efficient DH-PFS / signatures)
 *
 * Curve specification:
 * + Field math: Fp^2 with p = 2^127-1
 * + Curve shape: E:auxx + yy = duxxyy + 1 (mod Fp^2), u = 2 + i, a = -1, d=109
 * + Group size: #E = 4*q,
 * + q = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFA6261414C0DC87D3CE9B68E3B09E01A5
 *
 * Performance features:
 * + Most efficient field arithmetic: Fp^2 with p = 2^127-1
 * + Most efficient point group laws: Extended Twisted Edwards with a = -1 [5]
 * + Efficient endomorphism: 2-GLV-GLS [3]
 *
 * Security features:
 * + Timing-invariant arithmetic: Reduction is branchless
 * + Timing-invariant group laws: Twisted Edwards [5]
 * + Timing-invariant point multiplication: Using GLV-SAC exponent recoding [1]
 */

/*
 * References:
 *
 * [1] "Keep Calm and Stay with One" (Hernandez Longa Sanchez 2013)
 * http://eprint.iacr.org/2013/158
 * Introduces GLV-SAC exponent recoding
 *
 * [2] "Division by Invariant Integers using Multiplication" (Granlund Montgomery 1991)
 * http://pdf.aminer.org/000/542/596/division_by_invariant_integers_using_multiplication.pdf
 * Modulus on fixed field in constant time
 *
 * [3] "Endomorphisms for Faster Elliptic Curve Cryptography on a Large Class of Curves" (Galbraith Lin Scott 2008)
 * http://eprint.iacr.org/2008/194
 * Introduces 2-GLV-GLS method math
 *
 * [4] "Endomorphisms for Faster Elliptic Curve Cryptography on a Large Class of Curves" (Galbraith Lin Scott 2009)
 * http://www.iacr.org/archive/eurocrypt2009/54790519/54790519.pdf
 * Revises 2-GLV-GLS method math
 *
 * [5] "Twisted Edwards Curves Revisited" (Hisil Wong Carter Dawson 2008)
 * http://www.iacr.org/archive/asiacrypt2008/53500329/53500329.pdf
 * Introduces Extended Twisted Edwards group laws
 *
 * [6] "Fast and compact elliptic-curve cryptography" (Hamburg 2012)
 * http://eprint.iacr.org/2012/309
 * T = T1*T2 trick in Extended Twisted Edwards group laws
 */

/*
 * from [3]:
 *
 * y = sqrt(q-1) (mod q)
 *
 * In Twisted Edwards affine coordinates:
 *
 * endo(x,y) = (sqrt(conj(u)/u)*conj(x), conj(y)), p = 2^127-1, u = 2 + i
 * endo(P) = y*P
 */

// GCC: Use builtin 128-bit type
union leg {
	u128 w;
	u64 i[2];
};

// Load leg from endian-neutral data bytes
static fp_load(const u8 *x, leg &r) {
	r.i[0] = getLE64(*(u64*)x);
	r.i[1] = getLE64(*(u64*)(x + 8));
}

// Save leg to endian-neutral data bytes
static fp_save(const leg &x, u8 *r) {
	*(u64*)r = getLE64(x.i[0]);
	*(u64*)(r + 8) = getLE64(x.i[1]);
}

/*
 * 127-bit F(p) finite field arithmetic
 *
 * This is simply bigint math modulo Mersenne prime p = (2^^127 - 1),
 * which admits perhaps the simplest, timing-invariant reduction.
 *
 * 2^^31 - 1 : Good for ARM systems, but extension fields are not ideal
 * + Fp^7 -> 217-bit keys, too far from targetted security level
 * + Weil Descent attacks apply to Fp^8/9
 *
 * Other prime (2^^61 - 1): Pretty far from a word size.
 *
 * I care mainly about server performance, with 64-bit Linux VPS in mind, and
 * the Intel x86-64 instruction set has a fast 64x64->128 multiply instruction
 * that we can exploit to simplify the code and speed up math on this field.
 */

// TODO: Detect and fail on big-endian platforms
// TODO: Does this reduce 2^127-1 to zero?

static CAT_INLINE bool fp_iszero(const leg &r) {
	return r.w == 0;
}

// r = -a
static CAT_INLINE void fp_neg(const leg &a, leg &r) {
	// Uses 1a 1r
	u128 s = 0 - a;

	// Reduce
	r.w = 0 - (s + ((u64)(s >> 64) >> 63));

	// Eliminate high bit
	r.i[1] &= 0x7fffffffffffffffULL;
}

// r = r + 1
static CAT_INLINE void fp_add1(leg &r) {
	// Uses 1a 1r
	u128 s = r.w + 1;

	// Reduce
	r.w = 0 - (s + (((u64)(s >> 64) >> 63) ^ 1));

	// Eliminate high bit
	r.i[1] &= 0x7fffffffffffffffULL;
}

// r = a + b
static CAT_INLINE void fp_add(const leg &a, const leg &b, leg &r) {
	// Uses 1a 1r
	u128 s = a.w + b.w;

	// Reduce
	r.w = 0 - (s + (((u64)(s >> 64) >> 63) ^ 1));

	// Eliminate high bit
	r.i[1] &= 0x7fffffffffffffffULL;
}

// r = a - b
static CAT_INLINE void fp_sub(const leg &a, const leg &b, leg &r) {
	// Uses 1a 1r
	u128 s = a.w - b.w;

	// Reduce
	r.w = 0 - (s + ((u64)(s >> 64) >> 63));

	// Eliminate high bit
	r.i[1] &= 0x7fffffffffffffffULL;
}

// r = a * b
static CAT_INLINE void fp_mul(const leg &a, const leg &b, leg &r) {
	// Uses 4m 5a 1r
	// a.i[0] = A0, a.i[1] = A1, b.i[0] = B0, b.i[1] = B1

	// middle = A0*B1 + B1*B0 <= 2(2^64-1)(2^63-1)
	u128 middle = (u128)a.i[0] * b.i[1] + (u128)a.i[1] * b.i[0];
	// NOTE: Avoids a reduction here

	// low = A0*B0 < 2^^128
	u128 low = (u128)a.i[0] * b.i[0];

	register u64 ll = (u64)low;

	// middle += high half of low <= 2(2^64-1)(2^63-1) + (2^64-1)
	middle += (u64)(low >> 64);

	// high = A1*B1 <= (2^63-1)(2^63-1)
	u128 high = (u128)a.i[1] * b.i[1];

	// high += high half of middle <= (2^63-1)(2^63-1) + (2^64-1)
	high += (u64)(middle >> 64);

	// double high < 2^127
	high += high;

	// TEMP = lowpart(middle) : lowpart(low) < 2^128
	// Reduce TEMP < 2^127
	// Result = high + TEMP < 2^128
	register u64 next = (u64)middle;
	r.w = high + (next >> 63) + ll + ((u128)(next & 0x7fffffffffffffffULL) << 64);

	// Reduce result < 2^127
	r.w += r.i[1] >> 63;
	r.i[1] &= 0x7fffffffffffffffULL;
}

// r = a * b(small 32-bit constant)
static CAT_INLINE void fp_mul_smallk(const leg &a, const u32 b, leg &r) {
	// Uses 2m 4a 1r
	// Simplified from above:
	// a.i[0] = A0, a.i[1] = A1, B0 = 0|b, B1 = 0

	// middle = A0*B1 + B1*B0 <= 2(2^64-1)(2^63-1)
	u128 middle = (u128)a.i[1] * b;
	// NOTE: Avoids a reduction here

	// low = A0*B0 < 2^^128
	u128 low = (u128)a.i[0] * b;

	register u64 ll = (u64)low;

	// middle += high half of low <= 2(2^64-1)(2^63-1) + (2^64-1)
	middle += (u64)(low >> 64);

	// high = A1*B1 <= (2^63-1)(2^63-1)
	// high += high half of middle <= (2^63-1)(2^63-1) + (2^64-1)
	u128 high = (u64)(middle >> 64);

	// double high < 2^127
	high += high;

	// TEMP = lowpart(middle) : lowpart(low) < 2^128
	// Reduce TEMP < 2^127
	// Result = high + TEMP < 2^128
	register u64 next = (u64)middle;
	r.w = high + (next >> 63) + ll + ((u128)(next & 0x7fffffffffffffffULL) << 64);

	// Reduce result < 2^127
	r.w += r.i[1] >> 63;
	r.i[1] &= 0x7fffffffffffffffULL;
}

// r = a^2
static CAT_INLINE void fp_sqr(const leg &a, leg &r) {
	// Uses 3m 5a 1r
	// a.i[0] = A0, a.i[1] = A1

	// middle = A0*A1 + A1*A0 <= 2(2^64-1)(2^63-1)
	u128 middle = (u128)a.i[0] * a.i[1];
	middle += middle;
	// NOTE: Avoids a reduction here

	// low = A0*A0 < 2^^128
	u128 low = (u128)a.i[0] * a.i[0];

	register u64 ll = (u64)low;

	// middle += high half of low <= 2(2^64-1)(2^63-1) + (2^64-1)
	middle += (u64)(low >> 64);

	// high = A1*A1 <= (2^63-1)(2^63-1)
	u128 high = (u128)a.i[1] * a.i[1];

	// high += high half of middle <= (2^63-1)(2^63-1) + (2^64-1)
	high += (u64)(middle >> 64);

	// double high < 2^127
	high += high;

	// TEMP = lowpart(middle) : lowpart(low) < 2^128
	// Reduce TEMP < 2^127
	// Result = high + TEMP < 2^128
	register u64 next = (u64)middle;
	r.w = high + (next >> 63) + ll + ((u128)(next & 0x7fffffffffffffffULL) << 64);

	// Reduce result < 2^127
	r.w += r.i[1] >> 63;
	r.i[1] &= 0x7fffffffffffffffULL;
}

// r = 1/a
static CAT_INLINE void fp_inv(const leg &a, leg &r) {
	// Uses 126S 12M
	/*
	 * Euler's totient function:
	 * 1/a = a ^ (2^127 - 1 - 2)
	 *
	 * Use a short addition chain?
	 *
	 * l(127): 1 2 3 6 12 24 48 51 63 126 127 = 10 ops for 7 bits
	 * l(2^n-1) ~= n + l(n) - 1, n = 127 + 10 - 1 = 136
	 *
	 * Straight-forward squaring takes 138 ops.  Seems just fine.
	 */
	leg n1, n2, n3, n4, n5, n6;

	fp_sqr(a, n2);
	fp_mul(a, n2, n2);
	fp_sqr(n2, n3);
	fp_sqr(n3, n3);
	fp_mul(n3, n2, n3);
	fp_sqr(n3, n4);
	fp_sqr(n4, n4);
	fp_sqr(n4, n4);
	fp_sqr(n4, n4);
	fp_mul(n3, n4, n4);
	fp_sqr(n4, n5);
	fp_sqr(n5, n5);
	fp_sqr(n5, n5);
	fp_sqr(n5, n5);
	fp_sqr(n5, n5);
	fp_sqr(n5, n5);
	fp_sqr(n5, n5);
	fp_sqr(n5, n5);
	fp_mul(n5, n4, n5);
	fp_sqr(n5, n6);
	fp_sqr(n6, n6);
	fp_sqr(n6, n6);
	fp_sqr(n6, n6);
	fp_sqr(n6, n6);
	fp_sqr(n6, n6);
	fp_sqr(n6, n6);
	fp_sqr(n6, n6);
	fp_sqr(n6, n6);
	fp_sqr(n6, n6);
	fp_sqr(n6, n6);
	fp_sqr(n6, n6);
	fp_sqr(n6, n6);
	fp_sqr(n6, n6);
	fp_sqr(n6, n6);
	fp_sqr(n6, n6);
	fp_mul(n5, n6, n6);
	fp_sqr(n6, n1);
	fp_sqr(n1, n1);
	fp_sqr(n1, n1);
	fp_sqr(n1, n1);
	fp_sqr(n1, n1);
	fp_sqr(n1, n1);
	fp_sqr(n1, n1);
	fp_sqr(n1, n1);
	fp_sqr(n1, n1);
	fp_sqr(n1, n1);
	fp_sqr(n1, n1);
	fp_sqr(n1, n1);
	fp_sqr(n1, n1);
	fp_sqr(n1, n1);
	fp_sqr(n1, n1);
	fp_sqr(n1, n1);
	fp_sqr(n1, n1);
	fp_sqr(n1, n1);
	fp_sqr(n1, n1);
	fp_sqr(n1, n1);
	fp_sqr(n1, n1);
	fp_sqr(n1, n1);
	fp_sqr(n1, n1);
	fp_sqr(n1, n1);
	fp_sqr(n1, n1);
	fp_sqr(n1, n1);
	fp_sqr(n1, n1);
	fp_sqr(n1, n1);
	fp_sqr(n1, n1);
	fp_sqr(n1, n1);
	fp_sqr(n1, n1);
	fp_sqr(n1, n1);
	fp_mul(n1, n6, n1);
	fp_sqr(n1, n1);
	fp_sqr(n1, n1);
	fp_sqr(n1, n1);
	fp_sqr(n1, n1);
	fp_sqr(n1, n1);
	fp_sqr(n1, n1);
	fp_sqr(n1, n1);
	fp_sqr(n1, n1);
	fp_sqr(n1, n1);
	fp_sqr(n1, n1);
	fp_sqr(n1, n1);
	fp_sqr(n1, n1);
	fp_sqr(n1, n1);
	fp_sqr(n1, n1);
	fp_sqr(n1, n1);
	fp_sqr(n1, n1);
	fp_sqr(n1, n1);
	fp_sqr(n1, n1);
	fp_sqr(n1, n1);
	fp_sqr(n1, n1);
	fp_sqr(n1, n1);
	fp_sqr(n1, n1);
	fp_sqr(n1, n1);
	fp_sqr(n1, n1);
	fp_sqr(n1, n1);
	fp_sqr(n1, n1);
	fp_sqr(n1, n1);
	fp_sqr(n1, n1);
	fp_sqr(n1, n1);
	fp_sqr(n1, n1);
	fp_sqr(n1, n1);
	fp_sqr(n1, n1);
	fp_mul(n1, n6, n1);
	fp_sqr(n1, n1);
	fp_sqr(n1, n1);
	fp_sqr(n1, n1);
	fp_sqr(n1, n1);
	fp_sqr(n1, n1);
	fp_sqr(n1, n1);
	fp_sqr(n1, n1);
	fp_sqr(n1, n1);
	fp_sqr(n1, n1);
	fp_sqr(n1, n1);
	fp_sqr(n1, n1);
	fp_sqr(n1, n1);
	fp_sqr(n1, n1);
	fp_sqr(n1, n1);
	fp_sqr(n1, n1);
	fp_sqr(n1, n1);
	fp_mul(n1, n5, n1);
	fp_sqr(n1, n1);
	fp_sqr(n1, n1);
	fp_sqr(n1, n1);
	fp_sqr(n1, n1);
	fp_sqr(n1, n1);
	fp_sqr(n1, n1);
	fp_sqr(n1, n1);
	fp_sqr(n1, n1);
	fp_mul(n1, n4, n1);
	fp_sqr(n1, n1);
	fp_sqr(n1, n1);
	fp_sqr(n1, n1);
	fp_sqr(n1, n1);
	fp_mul(n1, n3, n1);
	fp_sqr(n1, n1);
	fp_mul(n1, a, n1);
	fp_sqr(n1, n1);
	fp_sqr(n1, n1);
	fp_mul(n1, a, r);
}


/*
 * 254-bit F(p^^2) optimal extension field (OEF) arithmetic
 *
 * This is simply complex number math (a + ib),
 * which is about 75% faster than 256-bit pseudo-Mersenne arithmetic for
 * multiplications, 100% faster for squaring, and 100% faster for inversion.
 */

struct guy {
	leg a, b;
};

static CAT_INLINE bool fe_iszero(const guy &r) {
	return fp_iszero(r.a) && fp_iszero(r.b);
}

// r = -a
static CAT_INLINE void fe_neg(guy &r) {
	// Uses 1A

	fp_neg(r.b);
}

// r = r + (1 + 0i)
static CAT_INLINE void fe_add1(guy &r) {
	// Uses 1A

	fp_add1(r.a);
}

// r = a + b
static CAT_INLINE void fe_add(const guy &a, const guy &b, guy &r) {
	// Uses 2A

	// Seems about comparable to 2^^256-c in performance
	fp_add(a.a, b.a, r.a);
	fp_add(a.b, b.b, r.b);
}

// r = a - b
static CAT_INLINE void fe_sub(const guy &a, const guy &b, guy &r) {
	// Uses 2A

	// Seems about comparable to 2^^256-c in performance
	fp_sub(a.a, b.a, r.a);
	fp_sub(a.b, b.b, r.b);
}

// r = a * b
static CAT_INLINE void fe_mul(const guy &a, const guy &b, guy &r) {
	// Uses 3M 5A

	// (a0 + ia1) * (b0 + ib1)
	// = (a0b0 - a1b1) + i(a1b0 + a0b1)
	// = (a0b0 - a1b1) + i( (a1 + a0) * (b1 + b0) - a1b1 - a0b0 )

	leg t0, t1;

	fp_mul(a.a, b.a, t0);
	fp_mul(a.b, b.b, t1);
	fp_sub(t0, t1, r.a);

	leg t2, t3, t4;

	fp_add(a.a, a.b, t2);
	fp_add(b.a, b.b, t3);
	fp_mul(t2, t3, t4);
	fp_sub(t4, t0, t2);
	fp_sub(t2, t1, r.b);
}

// r = a * b(small constant)
static CAT_INLINE void fe_mul_smallk(const guy &a, const u32 b, guy &r) {
	// Uses 2m

	fp_mul_smallk(a.a, b, r.a);
	fp_mul_smallk(a.b, b, r.b);
}

// r = a * a
static CAT_INLINE void fe_sqr(const guy &a, guy &r) {
	// Uses 2M 3A

	// (a + ib) * (a + ib)
	// = (aa - bb) + i(ab + ab)
	// = (a + b) * (a - b) + i(ab + ab)

	leg t0, t1;

	fp_add(a.a, a.b, t0);
	fp_sub(a.a, a.b, t1);
	fp_mul(t0, t1, r.a);

	fp_add(a.a, a.a, t0);
	fp_mul(t0, a.b, r.b);
}

// r = 1 / a
static void fe_inv(const guy &a, guy &r) {
	// Uses 2S 2M 2A 1I

	// 1/a = z'/(a*a + b*b)

	// In general, the cost for squaring is reduced by 1/n, n=extension field power
	// In this case, the inversion only needs to be done over a 2^^127 field instead of 2^^256

	leg t0, t1, t2;

	fp_sqr(a.a, t0);
	fp_sqr(a.b, t1);
	fp_add(t0, t1, t2);

	fp_inv(t2, t0);

	fp_neg(a.b, t1);

	fp_mul(a.a, t0, r.a);
	fp_mul(t1, t0, r.b);
}

// r = sqrt(a)
static void fe_sqrt(const guy &a, guy &r) {
	// Uses 125S

    // Square root for modulus p = 3 mod 4: a ^ (p + 1)/4
	// For p = 2^127 - 1, this reduces to a ^ (2^125)

	guy b;
	fe_sqr(a, b);

	for (int ii = 0; ii < 123; ++ii) {
		fe_sqr(b, b);
	}

	fe_sqr(b, r);
}

/*
 * m = a + b * y (mod N)  a, b < 2^127
 *
 * N: The number of points in the group, a large prime with small cofactor h
 * m: The secret scalar
 * y: The scalar multiplier performed by the endomorphism on the curve
 * r: Can be calculated from the relation: y = (1 + e*p)/r (mod N)
 *
 * This can be calculated, again from [1]:
 *
 * a = m - ( (m << 127)/N << 127 ) + (m*r)/N * d * r
 * b = (m << 127)/N * r - (m*r)/N << 127
 *
 * These are multiplications and divisions over integers larger than 2^127,
 * so special routines are provided for this decomposition.
 *
 * To make the scalar decomposition run in constant time, I recognized that
 * the divisions are all by a constant
 */

static void decompose(const u64 m[4], leg &a, leg &b) {
	// e = 1, p = 2^127 - 1
	// (1 + e*p) = 2^127
	// m*2^127 = m << 127
	// r = 
	// a = m - ((m << 127)/N << 127) + (
}

/*
 * Extended Twisted Edwards Group Laws
 */

struct ecpt {
	guy x, y, z, ta, tb;
};

static CAT_INLINE void ted_neg(ecpt &r) {
	// -(X : Y : T : Z) = (-X : Y : -T : Z)
	fe_neg(r.y);
	fe_neg(r.t);
}

static CAT_INLINE void ted_dbl(const ecpt &p, ecpt &r) {
	// Uses 3S 4M 5A

	// Ta <- X^2			= X^2
	fe_sqr(p.x, r.ta);

	// t1 <- Y^2			= Y^2
	guy t1;
	fe_sqr(p.y, t1);

	// Tb <- Ta + t1		= X^2 + Y^2
	fe_add(r.ta, t1, r.tb);

	// Ta <- t1 - Ta		= Y^2 - X^2
	fe_sub(t1, r.ta, r.ta);

	// Y2 <- Tb * Ta		Y2 = (X^2 + Y^2) * (Y^2 - X^2)
	fe_mul(r.tb, r.ta, r.y);

	// t1 <- Z^2			= Z^2
	fe_sqr(p.z, t1);

	// t1 <- t1 + t1		= 2 * Z^2
	fe_add(t1, t1, t1);

	// t1 <- t1 - Ta		= 2 * Z^2 - (Y^2 - X^2)
	fe_sub(t1, r.ta, t1);

	// Z2 <- Ta * t1		Z2 = (Y^2 - X^2) * (2 * Z^2 - (Y^2 - X^2))
	fe_mul(r.ta, t1, r.z);

	// Ta <- X + Y			= X + Y
	fe_add(p.x, p.y, r.ta);

	// Ta <- Ta^2			= (X + Y)^2
	fe_sqr(r.ta, r.ta);

	// Ta <- Ta - Tb		= 2 * X * Y = (X + Y)^2 - (X^2 + Y^2)
	fe_sub(r.ta, r.tb, r.ta);

	// X2 <- Ta * t1		X2 = 2 * X * Y * (2 * Z^2 - (Y^2 - X^2))
	fe_mul(r.ta, t1, r.x);

	// return 2P = (X2,Y2,Z2,{Ta,Tb}:T=Ta*Tb)
}

static CAT_INLINE void ted_add(const ecpt &a, const ecpt &b, ecpt &r, bool extended) {
	// TODO: Redo these
}

// Compute affine coordinates for (X,Y)
static CAT_INLINE void ted_affine(const ecpt &a, guy &x, guy &y) {
	// B = 1 / in.Z
	guy b;
	fe_inv(a.z, b);

	// out.X = B * in.X
	fe_mul(a.x, b, x);

	// out.Y = B * in.Y
	fe_mul(a.y, b, y);
}

// Solve for Y given the X point on a curve
static CAT_INLINE void ted_solve_y(ecpt &r) {
{
	// y = sqrt[(1 + x^2) / (1 - d*x^2)]

	// B = x^2
	guy b;
	fe_sqr(r.x, b);

	// C = 1/(1 - d*B)
	guy c;
	fe_mul_smallk(b, 109, c);
	fe_neg(c);
	fe_add1(c);
	fe_inv(c, c);

	// y = sqrt(C*(B+1))
	fe_add1(b);
	fe_mul(c, b, b);
	fe_sqrt(b, r.y);
}

/*
	As discussed in the 2008 Fouque-Lercier-Real-Valette paper
	"Fault Attack on Elliptic Curve with Montgomery Ladder Implementation",
	some implementations of ECC are vulnerable to active attack that cause
	the	victim to compute a scalar point multiply on the quadratic twist.
	The twist will usually be of insecure group order unless the designer
	spends extra time insuring both the curve and its twist have large
	prime group order.  Bernstein's Curve25519 prevents this attack by
	being twist-secure, for example, rather than validating the input.

	My curves are actually quadratic twists of Edwards curves by design. =)
	In my case the twisted curve has secure group order and the twist of my
	twist is back to an Edwards curve again, which may be of insecure order.

	To avoid any invalid point fault attacks in my cryptosystem, I validate
	that the input point (x,y) is on the curve.  I further check that the
	point is not x=0, which would be another way to introduce a fault,
	since x=0 is the identity element in Twisted Edwards coordinates and
	any multiple of x=0 is itself.

	I'm actually not sure if my code would be able to multiply a point
	that is not on the curve, but let's not find out!
*/

// Verify that the affine point (x,y) exists on the given curve
static CAT_INLINE bool ecpt_valid(const &ecpt a) {
	// 0 = 1 + d*x^2*y^2 + x^2 - y^2

	// If point is the additive identity x=0,
	if (fe_iszero(a.x)) {
		return false;
	}

	// B = x^2
	guy b;
	fe_sqr(a.x, b);

	// C = y^2
	guy c;
	fe_sqr(a.y, c);

	// E = B * C * d + 1 + B - C
	guy e;
	fe_mul(b, c, e);
	fe_mul(e, d, e);
	fe_add1(e);
	fe_add(e, b, e);
	fe_sub(e, c, e);

	// If the result is zero, it is on the curve
	return fe_iszero(e);
}

// R = kG
void Snowshoe::GenMul(const u32 k[8], ecpt &R) {
	// Multiplication by generator point
}

// R = kP
void Snowshoe::Mul(const u32 k[8], ecpt &P, ecpt &R) {
	// k = a + b*s, s = endomorphism scalar
	u32 a[4], b[4];
	decompose(k, a, b);

	// Calculate second base point Q = s*P
	ecpt Q;
	endomorph(P, Q);

	// Precompute table

	// Transform scalars

	// Simultaneous multiplication
}

// R = aP + bQ
void Snowshoe::SiMul(const u32 a[8], const ecpt &P, const u32 b[8], const ecpt &Q, ecpt &R) {
	// a = a0 + a1*s, s = endomorphism scalar
	u32 a0[4], a1[4];
	decompose(a, a0, a1);

	// b = b0 + b1*s, s = endomorphism scalar
	u32 b0[4], b1[4];
	decompose(b, b0, b1);

	// Calculate second base point P1 = s*P
	ecpt P1;
	endomorph(P, P1);

	// Calculate second base point Q1 = s*Q
	ecpt Q1;
	endomorph(Q, Q1);

	// Precompute table

	// Transform scalars

	// Simultaneous multiplication
}

