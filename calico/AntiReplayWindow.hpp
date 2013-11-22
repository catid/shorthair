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

#ifndef CAT_ANTI_REPLAY_WINDOW_HPP
#define CAT_ANTI_REPLAY_WINDOW_HPP

#include "Platform.hpp"

namespace cat {


class CAT_EXPORT AntiReplayWindow
{
	u64 _init_local, _init_remote;	// Initial version
	u64 _local, _remote;

	// Anti-replay sliding window
	static const int BITMAP_BITS = 1024; // Good for file transfer rates
	static const int BITMAP_WORDS = BITMAP_BITS / 64;
	u64 _bitmap[BITMAP_WORDS];

public:
	void Initialize(u64 local_iv, u64 remote_iv);

	bool Validate(u64 iv);
	u64 Accept(u64 iv);		// Returns normalized IV

	CAT_INLINE u64 PeekNormalizedLocal() { return _local - _init_local; }

	CAT_INLINE u64 NextLocal() { return _local++; }

	// NOTE: This one is reserved for stream mode
	CAT_INLINE u64 NextRemote() { return _remote++; }

	CAT_INLINE u64 LastAccepted() { return _remote; }
};


} // namespace cat

#endif // CAT_ANTI_REPLAY_WINDOW_HPP

