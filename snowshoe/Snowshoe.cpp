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
 * + Curve shape: E:auxx + yy = duxxyy + 1, u = 2 + i, a = -1, d=109
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
 * Alternative similar curves:
 *
 * u = 2 + i, a = -1, E:auxx+yy=duxxyy+1
 * d=109 : #E = 4*q, q = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFA6261414C0DC87D3CE9B68E3B09E01A5
 * d=139 : #E = 4*q, q = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFBE279B04A75463D09403332A27015D91
 * d=191 : #E = 4*q, q = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF826EDB49112B894254575EA3A0C8BDC5
 * d=1345: #E = 4*q, q = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF80490915366733181B4DC41442AAF491
 * d=1438: #E = 4*q, q = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC96E66D7F2A4B799044761AE30653065
 * d=1799: #E = 4*q, q = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF8FF32A5C1ACEC774E308CDB3636F2311
 * d=2076: #E = 4*q, q = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF81EBFEA8A9E1FB42ED4A6EBB16B24A91
 * d=2172: #E = 4*q, q = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF819920B3F8F71CD85DD3F4242C1B0E11
 * d=2303: #E = 4*q, q = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF9B3E69111FF31FA521F8B59CC48B4101
 * d=2377: #E = 4*q, q = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF94B9FB29B4A87B1DAEFA7A69FC19FD11
 * d=2433: #E = 4*q, q = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF8F4C87E0F8EB73ABCB41D9C4CF92FC41
 *
 * None of these are twist-secure.
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
 * Division on fixed field in constant time
 *
 * [3] "Endomorphisms for Faster Elliptic Curve Cryptography on a Large Class of Curves" (Galbraith Lin Scott 2008)
 * http://eprint.iacr.org/2008/194
 * Introduces 2-GLV-GLS method math
 *
 * [4] "Endomorphisms for Faster Elliptic Curve Cryptography on a Large Class of Curves" (Galbraith Lin Scott 2009)
 * http://www.iacr.org/archive/eurocrypt2009/54790519/54790519.pdf
 * More information on 2-GLV-GLS method math
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
 *
 * [9] "DECOMPOSITION OF AN INTEGER FOR EFFICIENT IMPLEMENTATION OF ELLIPTIC CURVE CRYPTOSYSTEM" (Park 2005)
 * http://www.mathnet.or.kr/mathnet/kms_tex/982868.pdf
 * Algorithm for splitting a scalar
 */

/*
 * 127-bit F(p) finite field arithmetic
 *
 * This is simply bigint math modulo Mersenne prime p = (2^127 - 1),
 * which admits perhaps the simplest, timing-invariant reduction.
 *
 * 2^31 - 1 : Good for ARM systems, but extension fields are not ideal
 * + Fp^7 -> 217-bit keys, too far from targetted security level
 * + Weil Descent attacks apply to Fp^8/9
 *
 * Other prime (2^61 - 1): Pretty far from a word size.
 *
 * I care mainly about server performance, with 64-bit Linux VPS in mind, and
 * the Intel x86-64 instruction set has a fast 64x64->128 multiply instruction
 * that we can exploit to simplify the code and speed up math on this field.
 */

// GCC: Use builtin 128-bit type
union leg {
	u128 w;
	u64 i[2];
};

// Load leg from endian-neutral data bytes (16)
static void fp_load(const u8 *x, leg &r) {
	r.i[0] = getLE64(*(u64*)x);
	r.i[1] = getLE64(*(u64*)(x + 8));
}

// Save leg to endian-neutral data bytes (16)
static void fp_save(const leg &x, u8 *r) {
	*(u64*)r = getLE64(x.i[0]);
	*(u64*)(r + 8) = getLE64(x.i[1]);
}

// TODO: Detect and fail on big-endian platforms
// TODO: Validate these.

// Check if r is zero
static CAT_INLINE bool fp_iszero(const leg &r) {
	return r.w == 0;
}

// Verify that 0 <= r < p
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

// r = k
static CAT_INLINE void fp_set_smallk(const u32 k, leg &r) {
	r.w = k;
}

// r = 0
static CAT_INLINE void fp_zero(leg &r) {
	r.w = 0;
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

// r = r + (u32)k
static CAT_INLINE void fp_add_smallk(const u32 k, leg &r) {
	// Uses 1a 1r
	u128 s = r.w + k;

	// Reduce
	r.w = 0 - (s + (((u64)(s >> 64) >> 63) ^ 1));

	// Eliminate high bit
	r.i[1] &= 0x7fffffffffffffffULL;
}

// Reduce r < p in the case where r = p
static CAT_INLINE void fe_red1271(guy &r) {
	// Branchlessly check if all the bits are set
	u64 t = r.i[0] & (t.i[1] | 0x8000000000000000ULL);
	u32 tw = (u32)t & (u32)(t >> 32);
	tw &= tw >> 16;
	tw &= tw >> 8;
	tw &= tw >> 4;
	tw &= tw >> 2;
	tw &= tw >> 1;

	// If so, add 1 and roll it back to zero else result is unchanged
	fp_add_smallk(tw & 1, r);
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
	fp_sqr(n3, n4); fp_sqr(n4, n4);
	fp_sqr(n4, n4); fp_sqr(n4, n4);
	fp_mul(n3, n4, n4);
	fp_sqr(n4, n5); fp_sqr(n5, n5); fp_sqr(n5, n5); fp_sqr(n5, n5);
	fp_sqr(n5, n5); fp_sqr(n5, n5); fp_sqr(n5, n5); fp_sqr(n5, n5);
	fp_mul(n5, n4, n5);
	fp_sqr(n5, n6); fp_sqr(n6, n6); fp_sqr(n6, n6); fp_sqr(n6, n6);
	fp_sqr(n6, n6); fp_sqr(n6, n6); fp_sqr(n6, n6); fp_sqr(n6, n6);
	fp_sqr(n6, n6); fp_sqr(n6, n6); fp_sqr(n6, n6); fp_sqr(n6, n6);
	fp_sqr(n6, n6); fp_sqr(n6, n6); fp_sqr(n6, n6); fp_sqr(n6, n6);
	fp_mul(n5, n6, n6);
	fp_sqr(n6, n1); fp_sqr(n1, n1); fp_sqr(n1, n1); fp_sqr(n1, n1);
	fp_sqr(n1, n1); fp_sqr(n1, n1); fp_sqr(n1, n1); fp_sqr(n1, n1);
	fp_sqr(n1, n1); fp_sqr(n1, n1); fp_sqr(n1, n1); fp_sqr(n1, n1);
	fp_sqr(n1, n1); fp_sqr(n1, n1); fp_sqr(n1, n1); fp_sqr(n1, n1);
	fp_sqr(n1, n1); fp_sqr(n1, n1); fp_sqr(n1, n1); fp_sqr(n1, n1);
	fp_sqr(n1, n1); fp_sqr(n1, n1); fp_sqr(n1, n1); fp_sqr(n1, n1);
	fp_sqr(n1, n1); fp_sqr(n1, n1); fp_sqr(n1, n1); fp_sqr(n1, n1);
	fp_sqr(n1, n1); fp_sqr(n1, n1); fp_sqr(n1, n1); fp_sqr(n1, n1);
	fp_mul(n1, n6, n1);
	fp_sqr(n1, n1); fp_sqr(n1, n1); fp_sqr(n1, n1); fp_sqr(n1, n1);
	fp_sqr(n1, n1); fp_sqr(n1, n1); fp_sqr(n1, n1); fp_sqr(n1, n1);
	fp_sqr(n1, n1); fp_sqr(n1, n1); fp_sqr(n1, n1); fp_sqr(n1, n1);
	fp_sqr(n1, n1); fp_sqr(n1, n1); fp_sqr(n1, n1); fp_sqr(n1, n1);
	fp_sqr(n1, n1); fp_sqr(n1, n1); fp_sqr(n1, n1); fp_sqr(n1, n1);
	fp_sqr(n1, n1); fp_sqr(n1, n1); fp_sqr(n1, n1); fp_sqr(n1, n1);
	fp_sqr(n1, n1); fp_sqr(n1, n1); fp_sqr(n1, n1); fp_sqr(n1, n1);
	fp_sqr(n1, n1); fp_sqr(n1, n1); fp_sqr(n1, n1); fp_sqr(n1, n1);
	fp_mul(n1, n6, n1);
	fp_sqr(n1, n1); fp_sqr(n1, n1); fp_sqr(n1, n1); fp_sqr(n1, n1);
	fp_sqr(n1, n1); fp_sqr(n1, n1); fp_sqr(n1, n1); fp_sqr(n1, n1);
	fp_sqr(n1, n1); fp_sqr(n1, n1); fp_sqr(n1, n1); fp_sqr(n1, n1);
	fp_sqr(n1, n1); fp_sqr(n1, n1); fp_sqr(n1, n1); fp_sqr(n1, n1);
	fp_mul(n1, n5, n1);
	fp_sqr(n1, n1); fp_sqr(n1, n1); fp_sqr(n1, n1); fp_sqr(n1, n1);
	fp_sqr(n1, n1); fp_sqr(n1, n1); fp_sqr(n1, n1); fp_sqr(n1, n1);
	fp_mul(n1, n4, n1);
	fp_sqr(n1, n1); fp_sqr(n1, n1); fp_sqr(n1, n1); fp_sqr(n1, n1);
	fp_mul(n1, n3, n1);
	fp_sqr(n1, n1);
	fp_mul(n1, a, n1);
	fp_sqr(n1, n1);
	fp_sqr(n1, n1);
	fp_mul(n1, a, r);
}

/*
 * 254-bit GF(p^2) optimal extension field (OEF) arithmetic
 *
 * This is simply complex number math (a + ib),
 * which is about 75% faster than 256-bit pseudo-Mersenne arithmetic for
 * multiplications, 100% faster for squaring, and 100% faster for inversion.
 */

struct guy {
	leg a, b;
};

// Load guy from endian-neutral data bytes (32)
static void fe_load(const u8 *x, guy &r) {
	fp_load(x, r.a);
	fp_load(x + 16, r.b);
}

// Save guy to endian-neutral data bytes (32)
static void fe_save(const guy &x, u8 *r) {
	fp_save(x.a, r);
	fp_save(x.b, r + 16);
}

// Check if r is zero
static CAT_INLINE bool fe_iszero(const guy &r) {
	return fp_iszero(r.a) && fp_iszero(r.b);
}

// Validate that r is within field
static CAT_INLINE bool fe_infield(const guy &r) {
	return fp_infield(r.a) && fp_infield(r.b);
}

// Reduce r
static CAT_INLINE void fe_red1271(guy &r) {
	// If a or b = 2^127-1, set that one to 0.
	// NOTE: The math functions already ensure that a,b < 2^127

	fp_red1271(r.a);
	fp_red1271(r.b);
}

// r = (k + 0i)
static CAT_INLINE void fe_set_smallk(const u32 k, guy &r) {
	fp_set_smallk(k, r.a);
	fp_zero(r.b);
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

// r = r + (k + 0i)
static CAT_INLINE void fe_add_smallk(const u32 k, const guy &a, guy &r) {
	// Uses 1A

	fp_add_smallk(k, a.a, r.a);
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
 * #E'(Fp^2) = (p - 1)^2 + t^2
 * = 28948022309329048855892746252171976962839764946219840790663900086538002237076
 * ^ This is my secure group.
 *
 * #E(Fp^2) = (p + 1)^2 - t^2
 * = 28948022309329048855892746252171976963114662652758564302138142702555026159984
 * ^ This is the twist of my secure group, which is not secure.
 *
 * Solving for t and verifying both expressions by using [6]:
 *
 * p := 2^127-1;
 *
 * EP := 28948022309329048855892746252171976962839764946219840790663900086538002237076;
 * Factorization(EP);
 *
 * TP := 28948022309329048855892746252171976963114662652758564302138142702555026159984;
 * Factorization(TP);
 *
 * pm1s := (p - 1)*(p - 1);
 * pp1s := (p + 1)*(p + 1);
 *
 * tsqrp := pp1s - TP;
 * print tsqrp;
 *
 * tsqrm := EP - pm1s;
 * print tsqrm;
 *
 * print SquareRoot(tsqrm);
 * print SquareRoot(tsqrp);
 *
 * Yields:
 *
 * [ <2, 2>, <7237005577332262213973186563042994240709941236554960197665975021634500559269, 1> ]
 * [ <2, 4>, <3, 1>, <11, 1>, <181, 1>, <443, 1>, <1789, 1>, <3041, 1>, <80447, 1>,
 * <2427899077100477, 1>, <3220268376816859, 1>, <199822028697017221643157029, 1> ]
 * 202833513651576707726253299423256250000
 * 202833513651576707726253299423256250000
 * 14241963124919847500.0000000000
 * 14241963124919847500.0000000000
 *
 * Switching TP with EP above yields something that is not a perfect square, which
 * serves to validate the above expressions.
 *
 * from [3]: endo(P) = y*P
 *
 * t*y + (1 - p) = 0 (mod r)
 * y = (p - 1) * t^-1 (mod r)
 *
 * It should also be true that y = sqrt(-1) mod r
 *
 * Using [6]:
 *
 * t := 14241963124919847500;
 * r := 7237005577332262213973186563042994240709941236554960197665975021634500559269;
 * p := 2^127-1;
 *
 * y := (p - 1) * InverseMod(t, r) mod r;
 *
 * print y;
 * print Modsqrt(r - 1, r);
 * print y:Hex;
 * print Modsqrt(r - 1, r):Hex;
 *
 * Yields:
 *
 * 6675262090232833354261459078081456826396694204445414604517147996175437985167
 * 6675262090232833354261459078081456826396694204445414604517147996175437985167
 * 0xEC2108006820E1AB0A9480CCBB42BE2A827C49CDE94F5CCCBF95D17BD8CF58F
 * 0xEC2108006820E1AB0A9480CCBB42BE2A827C49CDE94F5CCCBF95D17BD8CF58F
 *
 * Now we should also verify that the homomorphism takes us from an affine
 * point and results in the same thing as multiplying by lambda:
 *
 * According to [5] when u = 2 + i, cx = sqrt(u/u');
 * the homomorphism V(x,y) = (c * x', y') = lambda * (x,y)
 *
 * TODO: Verify this actually works in MAGMA.
 */

static const u64 ENDO_LAMBDA[4] = {
	0xCBF95D17BD8CF58FULL,
	0xA827C49CDE94F5CCULL,
	0xB0A9480CCBB42BE2ULL
	0x0EC2108006820E1AULL
}

/*
 * Decompose a scalar k into two sub-scalars a, b s.t. a + b * y = k
 * using the decomposition algorithm from [9],
 * and bigint division algorithm from [2].
 */

static void ted_split(const u64 m[4], leg &a, leg &b) {
	// TODO: Read [9].
}

/*
 * Extended Twisted Edwards Group Laws [5]
 *
 * Curve: a*u*x^2 + y^2 = d*u*x^2*y^2 /Fp^2, p=2^127-1, a=-1, d=109, u=2+i
 */

static const u32 TED_D = 109;

struct ecpt {
	guy x, y, t, z;
};

// Load (x,y) from endian-neutral data bytes (64)
static void ted_load_xy(const u8 *a, ecpt &r) {
	fe_load(a, r.x);
	fe_load(a + 32, r.y);
}

// Save (x,y) to endian-neutral data bytes (64)
static void ted_save_xy(const ecpt &a, u8 *r) {
	fe_load(a.x, r);
	fe_load(a.y, r + 32);
}

// TODO: Generate a random generator point and its homomorphism.

// Generator point (a randomly selected point on the curve)
static const ecpt TED_GENPT = {
	{	// x
		{	// a
			0x16848FED55A2F740ULL,
			0x34FE19AE9BC66F8FULL
		},
		{	// b
			0x2C1C732968A9F645ULL,
			0x7FDF340E3FDBDED5ULL
		}
	},
	{	// y
		{	// a
			0x1254212326DF1DE1ULL,
			0x5C86D9E7FA584F56ULL
		},
		{	// b
			0x5A3840B05DCFDCCBULL,
			0x6202F71A1F84D7DEULL
		}
	},
	{	// t
		{	// a
			0x93E3B0F29F10E97DULL,
			0x73D22FFBBD0EB465ULL
		},
		{	// b
			0x82B867DDC01F3559ULL,
			0x3148E5AC334308FCULL
		}
	}
};

// r = -a
static CAT_INLINE void ted_neg(const ecpt &a, ecpt &r) {
	// -(X : Y : T : Z) = (-X : Y : -T : Z)

	fe_neg(a.x, r.x);
	fe_set(a.y, r.y);
	fe_neg(a.t, r.t);
	fe_set(a.z, r.z);
}

// r = a
static CAT_INLINE void ted_set(const ecpt &a, ecpt &r) {
	fe_set(a.x, r.x);
	fe_set(a.y, r.y);
	fe_set(a.t, r.t);
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
 *
 * TODO: Verify this is the right one to use.
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
 * Twisted Edwards Homomorphism [3]
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
static CAT_INLINE void ted_morph(const ecpt &p, ecpt &r) {
	// X2 <- X1'
	guy t1;
	fe_conj(p.x, t1);

	// X2 <- ENDO_XEK * X2
	fe_mul(t1, ENDO_XEK, r.x);

	// Y2 <- Y1'
	fe_conj(p.y, r.y);

	// TODO: Generate T, Z

	// TODO: Verify this works.
}

/*
 * Extended Twisted Edwards Doubling [5]
 *
 * (X2, Y2, T2, Z2) = 2 * (X1, Y1, Z1), where T2 = X2*Y2/Z2
 *
 * T2 is computed optionally when calc_t = true.
 * T2 is necessary for following ted_dbl by ted_add.
 *
 * Precondition: &p != &r
 */

// r = 2p
static CAT_INLINE void ted_dbl(const ecpt &p, ecpt &r, const bool z_one, const bool calc_t) {
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

	// If z = 1,
	if (z_one) {
		// t1 = 2
		fe_set_smallk(2, t1);
	} else {
		// t1 <- Z^2			= Z^2
		fe_sqr(p.z, t1);

		// t1 <- t1 + t1		= 2 * Z^2
		fe_add(t1, t1, t1);
	}

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

// b = a in ted_add() precomputed coordinates
static CAT_INLINE void ted_set_precomp(const ecpt &a, ecpt &b) {
	// b <- (X2 + Y2, Y2 - X2, 2 * T2, 2 * Z2)
	ted_add(a.x, a.y, b.x);
	ted_sub(a.y, a.x, b.y);
	ted_add(a.t, a.t, b.t);
	ted_add(a.z, a.z, b.z);
}

/*
 * Extended Twisted Edwards Dedicated Point Addition [5]
 *
 * WARNING: This function will fail horribly when a = b
 *
 * Using precomputed point coordinates from [1]:
 * (X3, Y3, T3, Z3) = (X1, Y1, T1, Z1) + (X2 + Y2, Y2 - X2, 2 * T2, 2 * Z2)
 *
 * Precondition: calc_t was set to true on last operation for a and b
 * Precondition: a != b
 */

// r = a + b
static CAT_INLINE void ted_add_ded(ecpt &a, ecpt &b, ecpt &r, const bool z2_one, const bool calc_t) {
	// Uses: 7M 6A with z2_one=false calc_t=false
	// z2_one=true: -1M + 1A
	// calc_t=true: +1M

	// C = w1 <- 2 * Z1 * T2 = t2 * z1
	guy w1;
	fe_mul(b.t, a.z, w1);

	// If z2 = 1,
	guy w2;
	if (z2_one) {
		// D <- 2 * T1 * Z2 = t1 + t1
		fe_add(a.t, a.t, w2);
	} else {
		// D <- 2 * T1 * Z2
		fe_mul(a.t, b.z, w2);
	}

	// E <- D + C
	guy w3;
	fe_add(w1, w2, w3);

	// H <- D - C
	guy w4;
	fe_sub(w2, w1, w4);

	// w2 <- Y1 + X1 = y1 + x1
	fe_add(a.x, a.y, w2);

	// A = w2 <- (Y1 - X1) * (Y2 + X2) = x2 * w2
	fe_mul(b.x, w2, w2);

	// w1 <- Y1 - X1 = y1 - x1
	fe_sub(a.y, a.x, w1);

	// B = w1 <- (Y1 + X1) * (Y2 - X2) = y2 * w1
	fe_mul(b.y, w1, w1);

	// F = r3 <- B - A = w1 - w2
	fe_sub(w1, w2, r.z);

	// G = w1 <- B + A = w1 + w2
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

/*
 * Extended Twisted Edwards Unified Point Addition [5]
 *
 * Using precomputed point coordinates from [1]:
 * (X3, Y3, T3, Z3) = (X1, Y1, T1, Z1) + (X2 + Y2, Y2 - X2, 2 * T2, 2 * Z2)
 *
 * Precondition: calc_t was set to true on last operation for a and b
 */

// r = a + b
static CAT_INLINE void ted_add(ecpt &a, ecpt &b, ecpt &r, const bool z2_one, const bool calc_t) {
	// Uses: 7M 6A 1m with z2_one=false calc_t=false
	// z2_one=true: -1M + 1A
	// calc_t=true: +1M

	// w1 <- T1 * 2 * T2 = t1 * t2
	guy w1;
	fe_mul(b.t, a.t, w1);

	// C = w1 <- 2 * d * T1 * T2 = w1 * d
	fe_mul_smallk(w1, TED_D, w1);

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
static CAT_INLINE void ted_affine(const ecpt &a, ecpt &r) {
	// B = 1 / in.Z
	guy b;
	fe_inv(a.z, b);

	// out.X = B * in.X
	fe_mul(a.x, b, r.x);

	// out.Y = B * in.Y
	fe_mul(a.y, b, r.y);

	// Final reduction
	fe_red1271(r.x);
	fe_red1271(r.y);
}

// Solve for Y given the X point on a curve
static CAT_INLINE void ted_solve_y(ecpt &r) {
{
	// TODO: Probably drop this from the codebase
	// y = sqrt[(1 + x^2) / (1 - d*x^2)]

	// B = x^2
	guy b;
	fe_sqr(r.x, b);

	// C = 1/(1 - d*B)
	guy c;
	fe_mul_smallk(b, TED_D, c);
	fe_neg(c, c);
	fe_add_smallk(1, c, c);
	fe_inv(c, c);

	// y = sqrt(C*(B+1))
	fe_add_smallk(1, b, b);
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
	fe_add_smallk(1, e);
	fe_add(e, b, e);
	fe_sub(e, c, e);

	// If the result is zero, it is on the curve
	return fe_iszero(e);
}

void Snowshoe::MaskScalar(u32 k[8]) {
	// Group order of the curve = r = 4*q word-mapped:
	// 0x3FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFE9898505303721F4F3A6DA38EC2780694
	//   (  07  )(  06  )(  05  )(  04  )(  03  )(  02  )(  01  )(  00  )

	// Clear low 2 bits (due to cofactor = 4)
	k[0] &= ~(u32)3;

	// Clear high 2 bits (due to p = 127 bits)
	// Clear next highest bit also to avoid going above group order
	k[7] &= ~(u32)0xE0000000;

	// Largest value after filtering:
	// 0x1FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC
	//   (  07  )(  06  )(  05  )(  04  )(  03  )(  02  )(  01  )(  00  )

	// NOTE: This should also work with most other group orders.
}

// R = kG
void Snowshoe::GenMul(const u32 k[8], ecpt &R) {
	// Multiplication by generator point

	// k = a + b*s, s = endomorphism scalar
	u32 a[4], b[4];
	decompose(k, a, b);

	// Precompute endomorphism

	ecpt P;
	ted_set(TED_GENPT, P);

	ecpt G;
	ted_set_precomp(P, G);

	// For each bit in k < r from left to right,
	for (int ii = 253; ii >= 0; --ii) {
		// temp <- [2]P
		ecpt temp;
		ted_dbl(P, temp, false, true);

		// If bit is set,
		if (k[ii / 32] & (1 << (ii % 32))) {
			ted_add_ded(temp, G, P, true, false);
		}
	}

	// TODO: Start by doing naive left-to-right double-add to verify that it works.
	// Check the result using MAGMA.
	// Then implement GLV-SAC from [1].
	// Verify the result again against the reference version.
	// Then implement the other two:
}

/*
 * Reference implementation 1: [k]G using left-to-right unified add
 */
void RefGenMul1(const u32 k[8], ecpt &R) {
	// P = generator point
	ecpt P;
	ted_set(TED_GENPT, P);

	// G = generator point in precomputed coordinates for ted_add()
	ecpt G;
	ted_set_precomp(P, G);

	bool seen_bit = false;

	// For each bit in k < r from left to right,
	for (int ii = 253; ii >= 0; --ii) {
		ecpt temp;

		// If seen any bits yet,
		if (seen_bit) {
			// temp <- [2]P
			ted_dbl(P, temp, false, true);
		}

		// If bit is set,
		if (k[ii / 32] & (1 << (ii % 32))) {
			ted_add(temp, G, P, true, false);
			seen_bit = true;
		} else if (seen_bit) {
			ted_set(temp, P);
		}
	}

	// Compute affine coordinates in R
	ted_affine(P, R);
}

/*
 * Reference implementation 2: [k]G using left-to-right dedicated add
 */
void RefGenMul2(const u32 k[8], ecpt &R) {
	// P = generator point
	ecpt P;
	ted_set(TED_GENPT, P);

	// G = generator point in precomputed coordinates for ted_add()
	ecpt G;
	ted_set_precomp(P, G);

	// For each bit in k < r from left to right,
	for (int ii = 253; ii >= 0; --ii) {
		ecpt temp;

		// If seen any bits yet,
		if (seen_bit) {
			// temp <- [2]P
			ted_dbl(P, temp, false, true);
		}

		// If bit is set,
		if (k[ii / 32] & (1 << (ii % 32))) {
			ted_add_ded(temp, G, P, true, false);
			seen_bit = true;
		} else if (seen_bit) {
			ted_set(temp, P);
		}
	}

	// Compute affine coordinates in R
	ted_affine(P, R);
}

/*
 * Reference 3: [k]G using homomorphism + left-to-right dedicated add
 */
void RefGenMul3(const u32 k[8], ecpt &R) {
	// P = generator point in precomputed coordinates for ted_add()
	ecpt P;
	ted_set_precomp(TED_GENPT, P);

	// Q = homormorphism of generator point in preomcputed coordinates
	ecpt W, Q;
	ted_morph(TED_GENPT, W);
	ted_set_precomp(W, Q);

	// W = generator point
	ted_set(TED_GENPT, W);

	// k = a + b*s, s = endomorphism scalar
	u32 a[4], b[4];
	ted_split(k, a, b);

	// For each bit in k < r from left to right,
	for (int ii = 126; ii >= 0; --ii) {
		ecpt temp;

		if (seen_bit) {
			// temp <- [2]P
			ted_dbl(W, temp, false, true); // Always generates T
		}

		// If bit is set,
		if (a[ii / 32] & (1 << (ii % 32))) {
			ted_add_ded(temp, P, W, true, true); // Generates T
			seen_bit = true;
		} else if (seen_bit) {
			ted_set(temp, W);
		}

		// If bit is set,
		if (b[ii / 32] & (1 << (ii % 32))) {
			ted_add_ded(temp, Q, W, true, false);
			seen_bit = true;
		} else if (seen_bit) {
			ted_set(temp, W);
		}
	}

	// Compute affine coordinates in R
	ted_affine(W, R);
}

void UnitTestGenMul() {
	u32 k[8];
	ecpt R1, R2, R3, R4;
	u8 a1[64], a2[64], a3[64], a4[64];

	for (int jj = 0; jj < 1000; ++jj) {
		random(k);
		MaskScalar(k);

		RefGenMul1(k, R1);
		RefGenMul2(k, R2);
		RefGenMul3(k, R3);
		GenMul(k, R4);

		ted_save_xy(R1, a1);
		ted_save_xy(R2, a2);
		ted_save_xy(R3, a3);
		ted_save_xy(R4, a4);

		for (int ii = 0; ii < 64; ++ii) {
			if (a1[ii] != a2[ii] ||
				a2[ii] != a3[ii] ||
				a3[ii] != a4[ii]) {
				return false;
			}
		}
	}

	return true;
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

