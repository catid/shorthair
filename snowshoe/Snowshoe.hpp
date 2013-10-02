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

#ifndef CAT_SNOWSHOE_HPP
#define CAT_SNOWSHOE_HPP

#include "Platform.hpp"

/*
 * Snowshoe
 *
 * Elliptic Curve Math
 */

namespace cat {

namespace snowshoe {


class Snowshoe {
public:
	static const u8 SCALAR_SIZE = 32;
	static const int POINT_SIZE = 64;

	struct dude {
		u32 k[8];
	};

	static void MulG(const dude &k, ecpt &R);
	static void Mul(const dude &k, const ecpt &P, ecpt &R);
	static void SiMul(const dude &a, const ecpt &P, const dude &b, const ecpt &Q, ecpt &R);

	static void Affine(ecpt &P);

	// Returns false if point is invalid input
	static bool Scrub(ecpt &P);

	static void Pack(const ecpt &P, u8 buffer[POINT_SIZE]);
	static void Unpack(const u8 buffer[POINT_SIZE], ecpt &P);
};


} // namespace snowshoe

} // namespace cat

#endif // CAT_SNOWSHOE_HPP

