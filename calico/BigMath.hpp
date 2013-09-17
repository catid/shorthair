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

#ifndef CAT_BIG_MATH_HPP
#define CAT_BIG_MATH_HPP

#include "Platform.hpp"

namespace cat {


/*
	Optimized 128-bit and 64-bit Arithmetic Macro Library


	CAT_ADD128(r_hi, r_lo, x_hi, x_lo)

		Accumulator is 128-bit, input x(hi:lo) is 128-bit.

		r(hi:lo) += x(hi:lo)

	CAT_PADD128(r_hi, r_lo, x)

		Accumulator is 128-bit, input x is 64-bit.

		r(hi:lo) += (u64)x

	CAT_MUL64(r_hi, r_lo, x, y)

		Product is 128-bit, inputs x,y are 64-bit.

		r(hi:lo) = x * y

	CAT_PMUL64(r_hi, r_lo, x, y)

		Product is 128-bit, inputs x,y are 64-bit.

		Pre-condition: MSB(x) = MSB(y) = 0

		r(hi:lo) = x * y

	CAT_MUL32(x, y)

		Implicitly casts arguments to 32-bit numbers.

		Product is 64-bit, inputs x,y are 32-bit.

		This macro exists because some compilers produce
		better code when an intrinsic is used for this.


	NOTES:

		All platforms have a 64-bit integer called cat::u64.
*/


//// Platform-specialized versions ////

#if defined(CAT_WORD_64)


#if defined(CAT_ASM_ATT) && defined(CAT_ISA_X86) // X86-64:

# define CAT_ADD128(r_hi, r_lo, x_hi, x_lo)	\
	CAT_ASM_BEGIN							\
		"addq %3, %1 \n\t"					\
		"adcq %2, %0"						\
		: "+r"(r_hi),"+r"(r_lo)				\
		: "r"(x_hi),"r"(x_lo) : "cc"		\
	CAT_ASM_END

# define CAT_MUL64(r_hi, r_lo, x, y)	\
	CAT_ASM_BEGIN						\
		"mulq %3"						\
		: "=a"(r_lo), "=d"(r_hi)		\
		: "a"(x), "r"(y) : "cc"			\
	CAT_ASM_END

# define CAT_PMUL64 CAT_MUL64


#elif defined(CAT_ASM_ATT) && defined(CAT_ISA_PPC) // PPC-64:

# define CAT_ADD128(r_hi, r_lo, x_hi, x_lo)	\
	CAT_ASM_BEGIN							\
		"addc %1, %1, %3 \n\t"				\
		"adde %0, %0, %2"					\
		: "+r"(r_hi),"+r"(r_lo)				\
		: "r"(x_hi),"r"(x_lo) : "cc"		\
	CAT_ASM_END

# define CAT_MUL64(r_hi, r_lo, x, y)		\
	{										\
		register u64 __x = x, __y = y;		\
		r_lo = __x * __y;					\
		CAT_ASM_BEGIN						\
			"mulhdu %0, %1, %2"				\
			: "=r" (r_hi)					\
			: "r" (__x), "r" (__y) : "cc"	\
		CAT_ASM_END							\
	}

# define CAT_PMUL64 CAT_MUL64


#elif defined(CAT_HAS_U128) // 128-bit compiler-emulated types:

# define CAT_ADD128(r_hi, r_lo, x_hi, x_lo)															\
	{																								\
		register u128 __r = ( ((u128)(r_hi) << 64) | (r_lo) ) + ( ((u128)(x_hi) << 64) | (x_lo) );	\
		r_hi = (u64)(__r >> 64);																	\
		r_lo = (u64)__r;																			\
	}

# define CAT_MUL64(r_hi, r_lo, x, y)			\
	{											\
		register u128 __r = (u128)(x) * (y);	\
		r_hi = (u64)(__r >> 64);				\
		r_lo = (u64)__r;						\
	}

# define CAT_PMUL64 CAT_MUL64


#elif defined(CAT_COMPILER_MSVC) // MSVC-64:

# define CAT_ADD128(r_hi, r_lo, x_hi, x_lo)	\
	{										\
		register u64 __x_lo = x_lo;			\
		r_lo += __x_lo;						\
		r_hi += x_hi;						\
		r_hi += (r_lo) < __x_lo;			\
	}

# define CAT_MUL64(r_hi, r_lo, x, y)	\
	r_lo = _umul128(x, y, &(r_hi));

# define CAT_PMUL64 CAT_MUL64

#endif // platforms


#else // 32-bit specialized versions:


#if defined(CAT_COMPILER_MSVC) // MSVC-32:

# define CAT_MUL32(A, B) __emulu((u32)(A), (u32)(B)) /* slightly faster in ICC */

#endif


#endif // CAT_WORD_64


//// Default versions ////

#if !defined(CAT_MUL32)
# define CAT_MUL32(x, y) ( (u64)( (u32)(x) ) * (u32)(y) )
#endif

#if !defined(CAT_ADD128)
# define CAT_ADD128(r_hi, r_lo, x_hi, x_lo)		\
	{											\
		register u64 __x_lo = x_lo;				\
		r_lo += __x_lo;							\
		r_hi += x_hi;							\
		r_hi += (r_lo) < __x_lo;				\
	}
#endif

#if !defined(CAT_PADD128)
# define CAT_PADD128(r_hi, r_lo, x)	\
	{								\
		register u64 __x = x;		\
		r_lo += __x;				\
		r_hi += (r_lo) < __x;		\
	}
#endif

#if !defined(CAT_PMUL64)
# define CAT_PMUL64(r_hi, r_lo, x, y)												\
	{																				\
		register u64 __x = x;														\
		register u64 __y = y;														\
		register u64 __m = CAT_MUL32(__x, __y >> 32) + CAT_MUL32(__x >> 32, __y);	\
		r_hi = CAT_MUL32(__x >> 32, __y >> 32);										\
		r_lo = CAT_MUL32(__x, __y);													\
		CAT_ADD128(r_hi, r_lo, __m >> 32, __m << 32);								\
	}
#endif

#if !defined(CAT_MUL64)
# define CAT_MUL64(r_hi, r_lo, x, y)					\
	{													\
		register u64 __x = x;							\
		register u64 __y = y;							\
		register u64 __m = CAT_MUL32(__x, __y >> 32);	\
		register u64 __n = CAT_MUL32(__x >> 32, __y);	\
		r_hi = CAT_MUL32(__x >> 32, __y >> 32);			\
		r_lo = CAT_MUL32(__x, __y);						\
		CAT_ADD128(r_hi, r_lo, __m >> 32, __m << 32);	\
		CAT_ADD128(r_hi, r_lo, __n >> 32, __n << 32);	\
	}
#endif


} // namespace cat

#endif // CAT_BIG_MATH_HPP
