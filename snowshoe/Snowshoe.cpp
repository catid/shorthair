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
 * [6] MAGMA Online Calculator
 * http://magma.maths.usyd.edu.au/calc/
 * Calculating constants required
 *
 * [7] "Fault Attack on Elliptic Curve with Montgomery Ladder Implementation" (Fouque Lercier Real Valette 2008)
 * http://www.di.ens.fr/~fouque/pub/fdtc08.pdf
 * Discussion on twist security
 *
 * [8] "Curve25519: new Diffie-Hellman speed records" (Bernstein 2006)
 * http://cr.yp.to/ecdh/curve25519-20060209.pdf
 * Example of a conservative elliptic curve cryptosystem
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

static CAT_INLINE bool fp_iszero(const leg &r) {
	return r.w == 0;
}

static CAT_INLINE bool fp_infield(const leg &r) {
	// If high bit is set,
	if ((r.i[1] >> 63) != 0) {
		// Not in field
		return false;
	}

	// If r == 2^127-1,
	if (r.i[0] == 0xffffffffffffffffULL &&
		r.i[1] == 0x7fffffffffffffffULL) {
		// Not in field
		return false;
	}

	return true;
}

// r = a
static CAT_INLINE void fp_set(const leg &a, leg &r) {
	r.w = a.w;
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

static CAT_INLINE bool fe_infield(const guy &r) {
	return fp_infield(r.a) && fp_infield(r.b);
}

// r = a
static CAT_INLINE void fe_set(const guy &a, guy &r) {
	// Uses 1A

	fp_set(a.a, r.a);
	fp_set(a.b, r.b);
}

// r = a'
static CAT_INLINE void fe_conj(const guy &a, guy &r) {
	// Uses 1A

	fp_set(a.a, r.a);
	fp_neg(a.b, r.b);
}

// r = -a
static CAT_INLINE void fe_neg(const guy &a, guy &r) {
	// Uses 2A

	fp_neg(a.a, r.a);
	fp_neg(a.a, r.b);
}

// r = r + (1 + 0i)
static CAT_INLINE void fe_add1(const guy &a, guy &r) {
	// Uses 1A

	fp_add1(a.a, r.a);
	fp_set(a.b, r.b);
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
	// NOTE: The inversion only needs to be done over a 2^^127 field instead of 2^^256

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
 * from [3]: endo(P) = y*P
 *
 * y(lambda)^2 + 1 = 0 (mod q)
 * = sqrt(-1) (mod q)
 * = sqrt(q-1) (mod q)
 * = Modsqrt(q-1,q) using [6]
 * = 0xEC2108006820E1AB0A9480CCBB42BE2A827C49CDE94F5CCCBF95D17BD8CF58F
 */

static const u64 ENDO_LAMBDA[4] = {
	0xCBF95D17BD8CF58FULL,
	0xA827C49CDE94F5CCULL,
	0xB0A9480CCBB42BE2ULL
	0x0EC2108006820E1AULL
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
 *
 * Curve: a*u*x^2 + y^2 = d*u*x^2*y^2 /Fp^2, p=2^127-1, a=-1, d=109, u=2+i
 */

static const u32 TED_D = 109;

struct ecpt {
	guy x, y, t, z;
};

// Generator point (a randomly selected point on the curve)
static const ecpt TED_GENPT = {
	{	// x
		{	// a
			0x0ULL,
			0x0ULL
		},
		{	// b
			0x0ULL,
			0x0ULL
		}
	},
	{	// y
		{	// a
			0x0ULL,
			0x0ULL
		},
		{	// b
			0x0ULL,
			0x0ULL
		}
	},
	{	// 2t
		{	// a
			0x0ULL,
			0x0ULL
		},
		{	// b
			0x0ULL,
			0x0ULL
		}
	}
};

static CAT_INLINE void ted_neg(const ecpt &a, ecpt &r) {
	// -(X : Y : T : Z) = (-X : Y : -T : Z)

	fe_neg(a.x, r.x);
	fe_set(a.y, r.y);
	fe_neg(a.t, r.t);
	fe_set(a.z, r.z);
}

/*
 * In Twisted Edwards affine coordinates:
 *
 * endo(x,y) = (sqrt(conj(u)/u)*conj(x), conj(y)), p = 2^127-1, u = 2 + i
 *
 * xek = sqrt(conj(u)/u)
 * = 119563271493748934302613455993671912329 + 68985359527028636873539608271459718931*i
 * = 0x59F30C694ED33218695AB4D883DE0B89 + 0x33E618D29DA66430D2B569B107BC1713*i
 *
 * MAGMA script using [6]:
 *
 * p := 2^127-1;
 * K<w> := GF(p^2);
 * xek := SquareRoot((2-w)/(2+w));
 * print xek;
 */

static const guy ENDO_XEK = {
	{	// Real part (a):
		0x695AB4D883DE0B89ULL,
		0x59F30C694ED33218ULL
	},
	{	// Imaginart part (b):
		0xD2B569B107BC1713ULL,
		0x33E618D29DA66430ULL
	}
};

/*
 * Twisted Edwards Endomorphism
 *
 * Input:
 *
 * Affine point p = (X1, Y1)
 *
 * Output:
 *
 * Affine point r = (X2, Y2)
 *
 * Y2 = conj(Y1)
 * X2 = ENDO_XEK * conj(X1)
 */

// r = ENDO_LAMBDA * p
static CAT_INLINE void ted_endo(const ecpt &p, ecpt &r) {
	// X2 <- X1'
	guy t1;
	fe_conj(p.x, t1);

	// X2 <- ENDO_XEK * X2
	fe_mul(t1, ENDO_XEK, r.x);

	// Y2 <- Y1'
	fe_conj(p.y, r.y);
}

/*
 * Extended Twisted Edwards Doubling [5]
 *
 * (X2, Y2, T2, Z2) = 2 * (X1, Y1, Z1), where T2 = X2*Y2/Z2
 *
 * T2 is computed optionally when calc_t = true.
 * T2 is necessary for following ted_dbl by ted_add.
 */

// r = 2p
static CAT_INLINE void ted_dbl(const ecpt &p, ecpt &r, const bool calc_t) {
	// Uses 4S 3M 6A when calc_t=false
	// calc_t=true: +1M

	// Ta <- X^2			= X^2
	guy Ta;
	fe_sqr(p.x, Ta);

	// t1 <- Y^2			= Y^2
	guy t1;
	fe_sqr(p.y, t1);

	// Tb <- Ta + t1		= X^2 + Y^2
	guy Tb;
	fe_add(Ta, t1, Tb);

	// Ta <- t1 - Ta		= Y^2 - X^2
	fe_sub(t1, Ta, Ta);

	// Y2 <- Tb * Ta		Y2 = (X^2 + Y^2) * (Y^2 - X^2)
	fe_mul(Tb, Ta, r.y);

	// t1 <- Z^2			= Z^2
	fe_sqr(p.z, t1);

	// t1 <- t1 + t1		= 2 * Z^2
	fe_add(t1, t1, t1);

	// t1 <- t1 - Ta		= 2 * Z^2 - (Y^2 - X^2)
	fe_sub(t1, Ta, t1);

	// Z2 <- Ta * t1		Z2 = (Y^2 - X^2) * (2 * Z^2 - (Y^2 - X^2))
	fe_mul(Ta, t1, r.z);

	// Ta <- X + Y			= X + Y
	fe_add(p.x, p.y, Ta);

	// Ta <- Ta^2			= (X + Y)^2
	fe_sqr(Ta, Ta);

	// Ta <- Ta - Tb		= 2 * X * Y = (X + Y)^2 - (X^2 + Y^2)
	fe_sub(Ta, Tb, Ta);

	// X2 <- Ta * t1		X2 = 2 * X * Y * (2 * Z^2 - (Y^2 - X^2))
	fe_mul(Ta, t1, r.x);

	// If t is wanted,
	if (calc_t) {
		fe_mul(Ta, Tb, r.t);
	}
}

/*
 * Extended Twisted Edwards Unified Point Addition [5]
 *
 * The dedicated point formula is too dangerous, since with simultaneous
 * multiplication going on it is tricky to prevent the a = b fault case
 * where the dedicated point formula fails.  I was not able to find any
 * research on this fault attack to see if it causes real problems so I
 * am playing it safe here.
 *
 * Using precomputed point coordinates from [1]:
 * (X3, Y3, T3, Z3) = (X1, Y1, T1, Z1) + (X2 + Y2, Y2 - X2, T2, 2 * Z2)
 *
 * Precondition: calc_t was set to true on last operation for a and b
 */

// r = a + b
static CAT_INLINE void ted_add(ecpt &a, ecpt &b, ecpt &r, const bool z2_one, const bool calc_t) {
	// Uses: 7M 6A 1m with z2_one=false calc_t=false
	// z2_one=true: -1M + 1A
	// calc_t=true: +1M

	// w1 <- T1 * T2 = t1 * t2
	guy w1;
	fe_mul(b.t, a.t, w1);

	// C = w1 <- 2 * d * T1 * T2 = w1 * 2d
	fe_mul_smallk(w1, 2 * TED_D, w1);

	// If z2 = 1,
	guy w2;
	if (z2_one) {
		// D = w2 <- 2 * Z1 * (Z2=1) = z1 + z1
		fe_add(a.z, a.z, w2);
	} else {
		// D = w2 <- Z1 * (2 * Z2) = z1 * z2
		fe_mul(a.z, b.z, w2);
	}

	// F = w3 <- D - C = w2 - w1
	guy w3;
	fe_sub(w2, w1, w3);

	// G = w4 <- D + C = w2 + w1
	guy w4;
	fe_add(w1, w2, w4);

	// w2 <- Y1 + X1 = y1 + x1
	fe_add(a.x, a.y, w2);

	// B = w2 <- (Y1 + X1) * (Y2 + X2) = w2 * x2
	fe_mul(b.x, w2, w2);

	// w1 <- Y1 - X1 = y1 - x1
	fe_sub(a.y, a.x, w1);

	// A = w1 <- (Y1 - X1) * (Y2 - X2) = w1 * y2
	fe_mul(b.y, w1, w1);

	// E = z3 <- B - A = w2 - w1
	fe_sub(w2, w1, r.z);

	// H = w1 <- B + A = w1 + w2
	fe_add(w1, w2, w1);

	// X3 = x3 <- E * F = r3 * w3
	fe_mul(r.z, w3, r.x);

	// If t is wanted,
	if (calc_t) {
		// T3 = t3 <- E * H = r3 * w1
		fe_mul(r.z, w1, r.t);
	}

	// Y3 = y3 <- G * H = w1 * w4
	fe_mul(w1, w4, r.y);

	// Z3 = z3 <- F * G = w3 * w4
	fe_mul(w3, w4, r.z);
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
	fe_mul_smallk(b, TED_D, c);
	fe_neg(c, c);
	fe_add1(c, c);
	fe_inv(c, c);

	// y = sqrt(C*(B+1))
	fe_add1(b, b);
	fe_mul(c, b, b);
	fe_sqrt(b, r.y);
}

/*
 * Input validation:
 *
 * When the input point is not validated or other countermeasures are not
 * in place, it is possible to provide an input point on the twist of the
 * curve.  As shown in [7] this can lead to an active attack on the
 * cryptosystem.
 *
 * Bernstein's Curve25519 [8] prevents this attack by being "twist-secure",
 * for example, rather than validating the input.
 *
 * To avoid any invalid point fault attacks in my cryptosystem, I validate
 * that the input point (x, y) is on the curve, which is a cheap operation.
 *
 * I further check that the point is not x = 0, which would be another way
 * to introduce a fault, since x = 0 is the identity element.
 *
 * The input needs to fit within the field, so the exceptional value of
 * 2^127-1 must be checked for, since it is equivalent to 0.
*/

// Verify that the affine point (x, y) exists on the given curve
static CAT_INLINE bool ecpt_valid(const &ecpt a) {
	// 0 = 1 + 109*x^2*y^2 + x^2 - y^2

	// If point is outside of field,
	if (!fe_infield(a.x) || !fe_infield(a.y)) {
		return false;
	}

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
	fe_mul_smallk(e, TED_D, e);
	fe_add1(e);
	fe_add(e, b, e);
	fe_sub(e, c, e);

	// If the result is zero, it is on the curve
	return fe_iszero(e);
}

// R = kG
void Snowshoe::GenMul(const u32 k[8], ecpt &R) {
	// Multiplication by generator point

	// k = a + b*s, s = endomorphism scalar
	u32 a[4], b[4];
	decompose(k, a, b);
}

// R = kP
void Snowshoe::Mul(const u32 k[8], ecpt &P, ecpt &R) {
	// k = a + b*s, s = endomorphism scalar
	u32 a[4], b[4];
	decompose(k, a, b);

	// Calculate second base point Q = s*P
	ecpt Q;
	ted_endo(P, Q);

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
	ted_endo(P, P1);

	// Calculate second base point Q1 = s*Q
	ecpt Q1;
	ted_endo(Q, Q1);

	// Precompute table

	// Transform scalars

	// Simultaneous multiplication
}

