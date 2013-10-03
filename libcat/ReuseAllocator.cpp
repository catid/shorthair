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

#include "ReuseAllocator.hpp"
#include "Enforcer.hpp"
using namespace cat;


//// ReuseAllocator

ReuseAllocator::ReuseAllocator()
{
	_buffer_bytes = 0;
	_acquire_head = 0;
	_release_head = 0;
}

void ReuseAllocator::Initialize(u32 buffer_bytes)
{
	Cleanup();

	_buffer_bytes = buffer_bytes;
}

void ReuseAllocator::Cleanup() {
	// For each ready buffer,
	for (BatchHead *next, *buffer = _acquire_head; buffer; buffer = next)
	{
		next = buffer->batch_next;

		// Deallocate
		u8 *pkt = reinterpret_cast<u8*>( buffer );
		delete []pkt;
	}

	// For each free buffer,
	for (BatchHead *next, *buffer = _release_head; buffer; buffer = next)
	{
		next = buffer->batch_next;

		// Deallocate
		u8 *pkt = reinterpret_cast<u8*>( buffer );
		delete []pkt;
	}

	_acquire_head = 0;
	_release_head = 0;
}

ReuseAllocator::~ReuseAllocator()
{
	Cleanup();
}

void *ReuseAllocator::Acquire(u32 /*bytes*/)
{
#ifdef CAT_THREADED_ALLOCATOR
	bool acquire_lock_held = false;
#endif

	// If it looks like the acquire list has more,
	if (_acquire_head)
	{
#ifdef CAT_THREADED_ALLOCATOR
		acquire_lock_held = true;

		_acquire_lock.Enter();
#endif

		BatchHead *last = _acquire_head;

		// If found,
		if (last)
		{
			// Update list
			BatchHead *next = last->batch_next;
			_acquire_head = next;

#ifdef CAT_THREADED_ALLOCATOR
			_acquire_lock.Leave();
#endif

			//CAT_WARN("ReuseAllocator") << "Reused an acquire-list buffer of size " << _buffer_bytes;

			return last;
		}
	}

	// End up here if the acquire list was empty

	// If it looks like the release list has more,
	if (_release_head)
	{
		// Escalate lock and steal from release list
#ifdef CAT_THREADED_ALLOCATOR
		_release_lock.Enter();
#endif
		BatchHead *last = _release_head;
		_release_head = 0;
#ifdef CAT_THREADED_ALLOCATOR
		_release_lock.Leave();
#endif

		// If found,
		if (last)
		{
#ifdef CAT_THREADED_ALLOCATOR
			if (!acquire_lock_held)
				_acquire_lock.Enter();
#endif

			BatchHead *next = last->batch_next;
			_acquire_head = next;

#ifdef CAT_THREADED_ALLOCATOR
			_acquire_lock.Leave();
#endif

			//CAT_WARN("ReuseAllocator") << "Reused a release-list buffer of size " << _buffer_bytes;

			return last;
		}
	}

#ifdef CAT_THREADED_ALLOCATOR
	// If need to release lock,
	if (acquire_lock_held)
		_acquire_lock.Leave();
#endif

	// Allocate without lock held
	BatchHead *buffer = reinterpret_cast<BatchHead*>( new u8[_buffer_bytes] );

	//CAT_WARN("ReuseAllocator") << "Had to allocate a new buffer of size " << _buffer_bytes;

	return buffer;
}

void ReuseAllocator::ReleaseBatch(const BatchSet &set)
{
	if (!set.head) return;

#if defined(CAT_DEBUG)
	BatchHead *node;
	for (node = set.head; node->batch_next; node = node->batch_next);

	CAT_DEBUG_ENFORCE(node == set.tail);
#endif // CAT_DEBUG

#ifdef CAT_THREADED_ALLOCATOR
	_release_lock.Enter();
#endif
	set.tail->batch_next = _release_head;
	_release_head = set.head;
#ifdef CAT_THREADED_ALLOCATOR
	_release_lock.Leave();
#endif
}
