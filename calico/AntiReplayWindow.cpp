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
	ARE DISCLAIMED.	 IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
	LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
	CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
	SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
	INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
	CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
	ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
	POSSIBILITY OF SUCH DAMAGE.
*/

#include "AntiReplayWindow.hpp"
using namespace cat;

void AntiReplayWindow::Initialize(u64 local_iv, u64 remote_iv)
{
	_init_local = _local = local_iv;
	_init_remote = _remote = remote_iv;

	CAT_OBJCLR(_bitmap);
}

bool AntiReplayWindow::Validate(u64 iv)
{
	// Check how far in the past this IV is
	int delta = (int)(_remote - iv);

	// If it is in the past,
	if (delta >= 0)
	{
		// Check if we have kept a record for this IV
		if (delta >= BITMAP_BITS) return false;

		// If it was seen, abort
		const u64 mask = (u64)1 << (delta & 63);
		if (_bitmap[delta >> 6] & mask) return false;
	}

	return true;
}

u64 AntiReplayWindow::Accept(u64 iv)
{
	// Check how far in the past/future this IV is
	int delta = (int)(iv - _remote);

	// If it is in the future,
	if (delta > 0)
	{
		// If it would shift out everything we have seen,
		if (delta >= BITMAP_BITS)
		{
			// Set low bit to 1 and all other bits to 0
			_bitmap[0] = 1;
			CAT_CLR(&_bitmap[1], sizeof(_bitmap) - sizeof(u64));
		}
		else
		{
			const int word_shift = delta >> 6;
			const int bit_shift = delta & 63;

			// Shift replay window
			if (bit_shift > 0)
			{
				u64 last = _bitmap[BITMAP_WORDS - 1 - word_shift];
				for (int ii = BITMAP_WORDS - 1; ii >= word_shift + 1; --ii)
				{
					u64 x = _bitmap[ii - word_shift - 1];
					_bitmap[ii] = (last << bit_shift) | (x >> (64-bit_shift));
					last = x;
				}
				_bitmap[word_shift] = last << bit_shift;
			}
			else
			{
				for (int ii = BITMAP_WORDS - 1; ii >= word_shift; --ii)
					_bitmap[ii] = _bitmap[ii - word_shift];
			}

			// Zero the words we skipped
			for (int ii = 0; ii < word_shift; ++ii)
				_bitmap[ii] = 0;

			// Set low bit for this IV
			_bitmap[0] |= 1;
		}

		// Only update the IV if the MAC was valid and the new IV is in the future
		_remote = iv;
	}
	else // Process an out-of-order packet
	{
		delta = -delta;

		// Set the bit in the bitmap for this IV
		_bitmap[delta >> 6] |= (u64)1 << (delta & 63);
	}

	return iv - _init_remote;
}

