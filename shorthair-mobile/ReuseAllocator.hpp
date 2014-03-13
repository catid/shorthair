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

#ifndef CAT_REUSE_ALLOCATOR_HPP
#define CAT_REUSE_ALLOCATOR_HPP

#include "IAllocator.hpp"

// If multi-threaded allocator is used,
#ifdef CAT_THREADED_ALLOCATOR
#include "Mutex.hpp"
#endif

namespace cat {


/*
	The reuse allocator is optimized to react to runtime requirements
	by keeping previously allocated buffers around for later re-use.

	These buffers are not aligned and are allocated off the CRT heap.

	All buffers are the same size.

	Allocation and deallocation are thread-safe.  It is optimized to
	be used for allocating in one thread and deallocating in another,
	since it uses two locks and only causes contention if the allocator
	runs out of space and needs to lazily move all the freed buffers
	into the acquire list.  In any case, the lock time is minimized. 
*/

class CAT_EXPORT ReuseAllocator : public IAllocator
{
	u32 _buffer_bytes;

#ifdef CAT_THREADED_ALLOCATOR
	Mutex _acquire_lock;
#endif
	BatchHead * volatile _acquire_head;

#ifdef CAT_THREADED_ALLOCATOR
	Mutex _release_lock;
#endif
	BatchHead * volatile _release_head;

	// This interface really doesn't make sense for this allocator
	CAT_INLINE void *Resize(void *ptr, u32 bytes) { return 0; }
	CAT_INLINE void Release(void *buffer) {}
	CAT_INLINE u32 AcquireBatch(BatchSet &set, u32 count, u32 bytes = 0) { return 0; }

	void Cleanup();

public:
	ReuseAllocator();
	virtual ~ReuseAllocator();

	void Initialize(u32 buffer_bytes);

	CAT_INLINE u32 GetBufferBytes() {
		return _buffer_bytes;
	}

	CAT_INLINE bool Valid() {
		// Invalid until Initialize()
		return _buffer_bytes != 0;
	}

	// NOTE: Bytes parameter is ignored
	void *Acquire(u32 bytes = 0);

	// Release a number of buffers simultaneously
	void ReleaseBatch(const BatchSet &set);
};


} // namespace cat

#endif // CAT_BUFFER_ALLOCATOR_HPP
