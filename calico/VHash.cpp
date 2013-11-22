/*
	Copyright (c) 2012 Christopher A. Taylor.  All rights reserved.

	Redistribution and use in source and binary forms, with or without
	modification, are permitted provided that the following conditions are met:

	* Redistributions of source code must retain the above copyright notice,
	  this list of conditions and the following disclaimer.
	* Redistributions in binary form must reproduce the above copyright notice,
	  this list of conditions and the following disclaimer in the documentation
	  and/or other materials provided with the distribution.
	* Neither the name of LibCat nor the names of its contributors may be used
	  to endorse or promote products derived from this software without
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

#include "VHash.hpp"
#include "BigMath.hpp"
#include "EndianNeutral.hpp"
using namespace cat;

static const u64 p64 = 0xfffffffffffffeffULL;	// 2^64 - 257 prime
static const u64 m62 = 0x3fffffffffffffffULL;	// 62-bit mask
static const u64 m63 = 0x7fffffffffffffffULL;	// 63-bit mask
static const u64 m64 = 0xffffffffffffffffULL;	// 64-bit mask
static const u64 mpoly = 0x1fffffff1fffffffULL;	// poly key mask


//// Primitive functions

// Pre-condition: words >= 2, words is a multiple of 2 (128 bits)
static void NH128(const u64 *data, const u64 *key, int words, u64 &a_hi, u64 &a_lo)
{
	register u64 r_hi, r_lo;

	// Unroll first loop
	CAT_MUL64(r_hi, r_lo, getLE(data[0]) + key[0], getLE(data[1]) + key[1]);

	// For each remaining block:
	for (;;)
	{
		// Exit condition
		words -= 2;
		if (words <= 0) break;

		data += 2;
		key += 2;

		register u64 t_hi, t_lo;
		CAT_MUL64(t_hi, t_lo, getLE(data[0]) + key[0], getLE(data[1]) + key[1]);
		CAT_ADD128(r_hi, r_lo, t_hi, t_lo);
	}

	a_hi = r_hi;
	a_lo = r_lo;
}

// Pre-condition: words >= 8, words is a multiple of 8 (512 bits)
static void NH512(const u64 *data, const u64 *key, int words, u64 &a_hi, u64 &a_lo)
{
	register u64 r_hi = 0, r_lo = 0;

	// For each block:
	for (;;)
	{
		register u64 t_hi, t_lo;
		CAT_MUL64(t_hi, t_lo, getLE(data[0]) + key[0], getLE(data[1]) + key[1]);
		CAT_ADD128(r_hi, r_lo, t_hi, t_lo);
		CAT_MUL64(t_hi, t_lo, getLE(data[2]) + key[2], getLE(data[3]) + key[3]);
		CAT_ADD128(r_hi, r_lo, t_hi, t_lo);
		CAT_MUL64(t_hi, t_lo, getLE(data[4]) + key[4], getLE(data[5]) + key[5]);
		CAT_ADD128(r_hi, r_lo, t_hi, t_lo);
		CAT_MUL64(t_hi, t_lo, getLE(data[6]) + key[6], getLE(data[7]) + key[7]);
		CAT_ADD128(r_hi, r_lo, t_hi, t_lo);

		// Exit condition
		words -= 8;
		if (words <= 0) break;

		data += 8;
		key += 8;
	}

	a_hi = r_hi;
	a_lo = r_lo;
}

static void PolyStep(u64 &r_hi, u64 &r_lo, const u64 k_hi, const u64 k_lo, const u64 m_hi, const u64 m_lo)
{
	u64 a_hi = r_hi, a_lo = r_lo;

	// compute ab*cd, put bd into result registers
	u64 t1_hi, t1_lo, t2_hi, t2_lo, t3_hi, t3_lo;
	CAT_PMUL64(t3_hi, t3_lo, a_lo, k_hi);
	CAT_PMUL64(t2_hi, t2_lo, a_hi, k_lo);
	CAT_PMUL64(t1_hi, t1_lo, a_hi, k_hi << 1);
	CAT_PMUL64(a_hi, a_lo, a_lo, k_lo);

	// add 2 * ac to result
	CAT_ADD128(a_hi, a_lo, t1_hi, t1_lo);

	// add together ad + bc
	CAT_ADD128(t2_hi, t2_lo, t3_hi, t3_lo);

	// now (a_hi, a_lo), (t2_lo, 2*t2_hi) need summing
	// first add the high registers, carrying into t2_hi
	CAT_PADD128(t2_hi, a_hi, t2_lo);

	// double t2_hi and add top bit of a_hi
	t2_hi = (t2_hi << 1) + (a_hi >> 63);
	a_hi &= m63;

	// now add the low registers
	CAT_ADD128(a_hi, a_lo, m_hi, m_lo);
	CAT_PADD128(a_hi, a_lo, t2_hi);

	r_hi = a_hi;
	r_lo = a_lo;
}

static u64 Level3Hash(u64 p_hi, u64 p_lo, u64 k_hi, u64 k_lo, u64 len)
{
	u64 r_hi, r_lo, t;

	// fully reduce (p1,p2)+(len,0) mod 2^^127-1
	t = p_hi >> 63;
	p_hi &= m63;
	CAT_ADD128(p_hi, p_lo, len, t);

	// At this point, (p1,p2) is at most 2^127+(len<<64)
	t = (p_hi > m63) + ((p_hi == m63) && (p_lo == m64));
	CAT_PADD128(p_hi, p_lo, t);
	p_hi &= m63;

	// compute (p1,p2)/(2^64-2^32) and (p1,p2)%(2^64-2^32)
	t = p_hi + (p_lo >> 32);
	t += (t >> 32);
	t += (u32)t > 0xfffffffeu;

	p_hi += (t >> 32);
	p_lo += (p_hi << 32);

	// compute (p_hi+k_hi)%p64 and (p2+k2)%p64
	p_hi += k_hi;
	p_hi += (0 - (p_hi < k_hi)) & 257;

	p_lo += k_lo;
	p_lo += (0 - (p_lo < k_lo)) & 257;

	// compute (p1+k1)*(p2+k2)%p64
	CAT_MUL64(r_hi, r_lo, p_hi, p_lo);
	t = r_hi >> 56;

	CAT_PADD128(t, r_lo, r_hi);
	r_hi <<= 8;

	CAT_PADD128(t, r_lo, r_hi);
	t += t << 8;

	r_lo += t;
	r_lo += (0 - (r_lo < t)) & 257;
	r_lo += (0 - (r_lo > p64-1)) & 257;

	return r_lo;
}


//// VHash

VHash::~VHash()
{
	CAT_SECURE_OBJCLR(_nhkey);
	CAT_SECURE_OBJCLR(_polykey);
	CAT_SECURE_OBJCLR(_l3key);
}

void VHash::SetKey(const u8 key[160])
{
	memcpy(_nhkey, key, sizeof(_nhkey));
	memcpy(_polykey, key + sizeof(_nhkey), sizeof(_polykey));
	memcpy(_l3key, key + sizeof(_nhkey) + sizeof(_polykey), sizeof(_l3key));

#if !defined(CAT_ENDIAN_LITTLE)
	// Fix byte order
	for (int ii = 0; ii < NH_KEY_WORDS; ++ii)
		swapLE(_nhkey[ii]);
	swapLE(_polykey[0]);
	swapLE(_polykey[1]);
	swapLE(_l3key[0]);
	swapLE(_l3key[1]);
#endif

	// Mask poly key
	_polykey[0] &= mpoly;
	_polykey[1] &= mpoly;
}

u64 VHash::Hash(const void *vdata, int bytes)
{
	const u64 *data = reinterpret_cast<const u64*>( vdata );
	int blocks = bytes / NHBYTES, remains = bytes % NHBYTES;

	u64 c_hi, c_lo;

	// Unroll first loop to avoid PolyStep()
	if (blocks > 0)
	{
		NH512(data, _nhkey, NH_KEY_WORDS, c_hi, c_lo);
		c_hi &= m62;
		CAT_ADD128(c_hi, c_lo, _polykey[0], _polykey[1]);

		data += NH_KEY_WORDS;
		--blocks;
	}
	else
	{
		if (remains)
		{
			// Copy to temporary location
			u64 temp[NHBYTES];
			memcpy(temp, data, remains);
			memset((u8*)temp + remains, 0, NHBYTES - remains);

			const int data_words = 2 * CAT_CEIL_UNIT(remains, 16);
			NH128(temp, _nhkey, data_words, c_hi, c_lo);
			c_hi &= m62;
			CAT_ADD128(c_hi, c_lo, _polykey[0], _polykey[1]);
		}
		else
		{
			c_hi = _polykey[0];
			c_lo = _polykey[1];
		}

		return Level3Hash(c_hi, c_lo, _l3key[0], _l3key[1], bytes);
	}

	// For each block,
	while (blocks-- > 0)
	{
		u64 r_hi, r_lo;
		NH512(data, _nhkey, NH_KEY_WORDS, r_hi, r_lo);
		r_hi &= m62;

		PolyStep(c_hi, c_lo, _polykey[0], _polykey[1], r_hi, r_lo);

		data += NH_KEY_WORDS;
	}

	// If any data remains,
	if (remains)
	{
		// Copy to temporary location
		u64 temp[NHBYTES];
		memcpy(temp, data, remains);
		memset((u8*)temp + remains, 0, NHBYTES - remains);

		u64 r_hi, r_lo;
		const int data_words = 2 * CAT_CEIL_UNIT(remains, 16);
		NH128(temp, _nhkey, data_words, r_hi, r_lo);
		r_hi &= m62;

		PolyStep(c_hi, c_lo, _polykey[0], _polykey[1], r_hi, r_lo);
	}

	return Level3Hash(c_hi, c_lo, _l3key[0], _l3key[1], bytes);
}
