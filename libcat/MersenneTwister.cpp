/*
	Copyright (c) 2009-2010 Christopher A. Taylor.  All rights reserved.

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

#include "MersenneTwister.hpp"
#include <cstring>
using namespace cat;
using namespace std;


MersenneTwister::MersenneTwister()
{
    state32 = &state[0].u[0];
}

// fix the initial state to ensure that the full generator period will occur
void MersenneTwister::enforcePeriod()
{
    static const u32 PARITY[4] = {0x00000001U, 0x00000000U, 0x00000000U, 0x13c9e684U};

    u32 inner = 0;

    // An odd number of parity bits set is OK
    inner ^= state32[0] & PARITY[0];
    inner ^= state32[1] & PARITY[1];
    inner ^= state32[2] & PARITY[2];
    inner ^= state32[3] & PARITY[3];
    inner ^= inner >> 16;
    inner ^= inner >> 8;
    inner ^= inner >> 4;
    inner ^= inner >> 2;
    inner ^= inner >> 1;
    if ((inner & 1)) return;

    // Otherwise, flip the lowest parity bit to make it odd
    for (u32 ii = 0; ii < 4; ++ii)
    {
        if (PARITY[ii])
        {
            state32[ii] ^= CAT_LSB32(PARITY[ii]);
            break;
        }
    }
}

// initialize the generator with a 32-bit seed
bool MersenneTwister::Initialize(u32 seed)
{
    state32[0] = seed;

    for (u32 ii = 1; ii < N32; ++ii)
        state32[ii] = 1812433253UL * (state32[ii-1] ^ (state32[ii-1] >> 30)) + ii;

    enforcePeriod();
    used = N32;

    return true;
}

// initialize with an array of seeds
bool MersenneTwister::Initialize(u32 *seeds, u32 words)
{
    u32 ii, jj, r, count, mid, lag, size = N32;

    if (size >= 623)        lag = 11;
    else if (size >= 68)    lag = 7;
    else if (size >= 39)    lag = 5;
    else                    lag = 3;

    mid = (size - lag) / 2;

    memset(state, 0x8b, sizeof(state));

    if (words+1 > N32)    count = words+1;
    else                count = N32;

#define FUNC1(x) ( ((x) ^ ((x) >> 27)) * (u32)1664525UL )
#define FUNC2(x) ( ((x) ^ ((x) >> 27)) * (u32)1566083941UL )

    r = FUNC1(state32[0]);
    state32[mid] += r;
    r += words;
    state32[mid + lag] += r;
    state32[0] = r;

    --count;
    for (ii = 1, jj = 0; (jj < count) && (jj < words); ++jj)
    {
        r = FUNC1(state32[ii] ^ state32[(ii + mid) % N32] ^ state32[(ii + N32 - 1) % N32]);
        state32[(ii + mid) % N32] += r;
        r += seeds[jj] + ii;
        state32[(ii + mid + lag) % N32] += r;
        state32[ii] = r;
        ++ii;
        ii %= N32;
    }
    for (; jj < count; ++jj)
    {
        r = FUNC1(state32[ii] ^ state32[(ii + mid) % N32] ^ state32[(ii + N32 - 1) % N32]);
        state32[(ii + mid) % N32] += r;
        r += ii;
        state32[(ii + mid + lag) % N32] += r;
        state32[ii] = r;
        ++ii;
        ii %= N32;
    }
    for (jj = 0; jj < N32; ++jj)
    {
        r = FUNC2(state32[ii] + state32[(ii + mid) % N32] + state32[(ii + N32 - 1) % N32]);
        state32[(ii + mid) % N32] ^= r;
        r -= ii;
        state32[(ii + mid + lag) % N32] ^= r;
        state32[ii] = r;
        ++ii;
        ii %= N32;
    }

#undef FUNC1
#undef FUNC2

    enforcePeriod();
    used = N32;

    return true;
}

// r != n, 0 < bits < 32
void MersenneTwister::shiftLeft128(MT128 *r, MT128 *n, u32 bits)
{
    r->u[0] = n->u[0] << bits;
    r->u[1] = (n->u[1] << bits) | (n->u[0] >> (32 - bits)); 
    r->u[2] = (n->u[2] << bits) | (n->u[1] >> (32 - bits)); 
    r->u[3] = (n->u[3] << bits) | (n->u[2] >> (32 - bits)); 
}

// r != n, 0 < bits < 32
void MersenneTwister::shiftRight128(MT128 *r, MT128 *n, u32 bits)
{
    r->u[0] = (n->u[0] >> bits) | (n->u[1] << (32 - bits));
    r->u[1] = (n->u[1] >> bits) | (n->u[2] << (32 - bits));
    r->u[2] = (n->u[2] >> bits) | (n->u[3] << (32 - bits));
    r->u[3] = n->u[3] >> bits; 
}

// a ^= (a << SL2BITS) ^ ((b >> SR1) & MSK) ^ (c >> SR2BITS) ^ (d{0..3} << SL1)
void MersenneTwister::round(MT128 *a, MT128 *b, MT128 *c, MT128 *d)
{
    MT128 x, y;

    shiftLeft128(&x, a, SL2BITS);
    shiftRight128(&y, c, SR2BITS);

    a->u[0] ^= x.u[0] ^ ((b->u[0] >> SR1) & MSK1) ^ y.u[0] ^ (d->u[0] << SL1);
    a->u[1] ^= x.u[1] ^ ((b->u[1] >> SR1) & MSK2) ^ y.u[1] ^ (d->u[1] << SL1);
    a->u[2] ^= x.u[2] ^ ((b->u[2] >> SR1) & MSK3) ^ y.u[2] ^ (d->u[2] << SL1);
    a->u[3] ^= x.u[3] ^ ((b->u[3] >> SR1) & MSK4) ^ y.u[3] ^ (d->u[3] << SL1);
}

// permute the existing state into a new one
void MersenneTwister::update()
{
    MT128 *r1 = state + N128 - 2;
    MT128 *r2 = state + N128 - 1;
    u32 ii;

    for (ii = 0; ii < N128 - POS1; ++ii)
    {
        round(state + ii, state + ii + POS1, r1, r2);
        r1 = r2;
        r2 = state + ii;
    }

    for (; ii < N128; ++ii)
    {
        round(state + ii, state + ii + POS1 - N128, r1, r2);
        r1 = r2;
        r2 = state + ii;
    }

    used = 0;
}

// generate a 32-bit random number
u32 MersenneTwister::Generate()
{
    if (used >= N32)
        update();

    return state32[used++];
}

// generate a series of random numbers to fill a buffer of any size
void MersenneTwister::Generate(void *buffer, int bytes)
{
    u8 *buffer8 = (u8 *)buffer;
    u32 words = bytes / 4;

    while (words > 0)
    {
        if (used >= N32)
            update();

        u32 remaining = N32 - used;
        u32 copying = words;
        if (copying > remaining) copying = remaining;

        memcpy(buffer8, state32 + used, copying*4);
        used += copying;
        words -= copying;
        buffer8 += copying*4;
    }

    switch (bytes % 4)
    {
    case 1:
        buffer8[0] = (u8)Generate();
        break;
    case 2:
        *(u16*)buffer8 = (u16)Generate();
        break;
    case 3:
        words = Generate();
        buffer8[0] = (u8)words;
        *(u16*)(buffer8+1) = (u16)(words >> 8);
        break;
    }
}


#include <cmath>
using namespace std;



#define ZIGNOR_C 128			       /* number of blocks */
#define ZIGNOR_R 3.442619855899	/* start of the right tail */
				   /* (R * phi(R) + Pr(X>=R)) * sqrt(2\pi) */
#define ZIGNOR_V 9.91256303526217e-3
#define M_RAN_INVM32	2.32830643653869628906e-010			  /* 1.0 / 2^32 */
#define ZIGNOR_INVM	M_RAN_INVM32

static u32 s_aiZigRm[ZIGNOR_C];
static double s_adZigXm[ZIGNOR_C + 1];

static void zig32NorInit(s32 iC, double dR, double dV)
{
	s32 i;
	double f, m31 = ZIGNOR_INVM * 2;

	f = exp(-0.5 * dR * dR);
	s_adZigXm[0] = dV / f; /* [0] is bottom block: V / f(R) */
	s_adZigXm[1] = dR;
	s_adZigXm[iC] = 0;

	for (i = 2; i < iC; ++i)
	{
		s_adZigXm[i] = sqrt(-2 * log(dV / s_adZigXm[i - 1] + f));
		f = exp(-0.5 * s_adZigXm[i] * s_adZigXm[i]);
	}
	/* compute ratio and implement scaling */
	for (i = 0; i < iC; ++i)
		s_aiZigRm[i] = (unsigned int)
			( (s_adZigXm[i + 1] / s_adZigXm[i]) / m31 );
	for (i = 0; i <= iC; ++i)
		s_adZigXm[i] *= m31;
}

void MersenneTwister::InitializeNor() {
	zig32NorInit(ZIGNOR_C, ZIGNOR_R, ZIGNOR_V);
}



static unsigned long ke[256];
static float we[256],fe[256];

void MersenneTwister::InitializeExp() {
	const double m2 = 4294967296.;
	double q, de=7.697117470131487, te=de, ve=3.949659822581572e-3;
	int i;

	/* Set up tables for REXP */
	q = ve/exp(-de);
	ke[0]=(de/q)*m2;
	ke[1]=0;

	we[0]=q/m2;
	we[255]=de/m2;

	fe[0]=1.;
	fe[255]=exp(-de);

	for(i=254;i>=1;i--)
	{
		de=-log(ve/de+exp(-de));
		ke[i+1]= (de/te)*m2;
		te=de;
		fe[i]=exp(-de);
		we[i]=de/m2;
	}
}

float MersenneTwister::Nor() {
	u32 i;
	s32 u;
	double x, y, f0, f1;
	
	for (;;)
	{
		u = (s32)Generate();
		i = Generate() & 0x7F;
		s32 abs_u = u < 0 ? -u : u;
		if ((unsigned int)abs_u < s_aiZigRm[i])/* first try the rectangles */
		{
			return u * s_adZigXm[i];
		}
		
		if (i == 0)									/* sample from the tail */
		{
			double x, y;
			do
			{	x = log(Uni()) / ZIGNOR_R;
				y = log(Uni());
			} while (-2 * y < x * x);

			return u < 0 ? x - ZIGNOR_R : ZIGNOR_R - x;
		}

		x = u * s_adZigXm[i];		   /* is this a sample from the wedges? */
		y = 0.5 * s_adZigXm[i] / ZIGNOR_INVM;      f0 = exp(-0.5 * (y * y - x * x) );
		y = 0.5 * s_adZigXm[i + 1] / ZIGNOR_INVM;  f1 = exp(-0.5 * (y * y - x * x) );
      	if (f1 + Generate() * ZIGNOR_INVM * (f0 - f1) < 1.0) {
			return x;
		}
	}
}

float MersenneTwister::Exp() {
	float x;
	u32 jz = Generate();
	u32 iz = jz & 255;

	if (jz < ke[iz]) {
		return jz * we[iz];
	}

	for(;;)
	{
		if(iz==0) {
			return (7.69711-log(Uni()));          /* iz==0 */
		}

		u32 jz = Generate();

		x=jz*we[iz];
		if( fe[iz]+Uni()*(fe[iz-1]-fe[iz]) < exp(-x) ) {
			return x;
		}

		/* initiate, try to exit for(;;) loop */
		jz=Generate();
		iz=(jz&255);
		if(jz<ke[iz]) return (jz*we[iz]);
	}
}

