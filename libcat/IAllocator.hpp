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

#ifndef CAT_I_ALLOCATOR_HPP
#define CAT_I_ALLOCATOR_HPP

#include "Platform.hpp"
#include <new>

namespace cat {


struct BatchHead;
class BatchSet;
class IAllocator;


// For batch allocations, this is the header attached to each one.  This header
// allows for the batched objects to be passed around with a BatchSet (below).
// Normal allocations do not use this header.
struct BatchHead
{
	BatchHead *batch_next;
};

// When passing around a batch of allocated space, use this object to represent
// the two ends of the batch for O(1) concatenation to other batches
class CAT_EXPORT BatchSet
{
public:
	BatchHead *head, *tail;

	CAT_INLINE BatchSet() {}
	CAT_INLINE BatchSet(BatchHead *h, BatchHead *t) { head = h; tail = t; }
	CAT_INLINE BatchSet(BatchHead *single)
	{
		head = tail = single;
		single->batch_next = 0;
	}

	CAT_INLINE BatchSet(const BatchSet &t)
	{
		head = t.head;
		tail = t.tail;
	}

	CAT_INLINE BatchSet &operator=(const BatchSet &t)
	{
		head = t.head;
		tail = t.tail;
		return *this;
	}

	CAT_INLINE void Clear()
	{
		head = tail = 0;
	}

	CAT_INLINE void PushBack(BatchHead *single)
	{
		if (tail) tail->batch_next = single;
		else head = single;
		tail = single;
		single->batch_next = 0;
	}

	CAT_INLINE void PushBack(const BatchSet &t)
	{
		// If parameter is the empty set,
		if (!t.head) return;

		// If we are an empty set,
		if (!head)
			head = t.head;
		else
			tail->batch_next = t.head;

		tail = t.tail;
	}
};


// Allocator interface
class CAT_EXPORT IAllocator
{
public:
	CAT_INLINE virtual ~IAllocator() {}

	// Returns true if allocator backing store was successfully initialized
	virtual bool Valid() { return true; }

	// Returns 0 on failure
	// May acquire more bytes than requested
    virtual void *Acquire(u32 bytes) = 0;

	template<class T>
	CAT_INLINE T *AcquireArray(u32 elements)
	{
		return reinterpret_cast<T*>( Acquire(sizeof(T) * elements) );
	}

	template<class T>
	CAT_INLINE T *AcquireObject()
	{
		return reinterpret_cast<T*>( Acquire(sizeof(T)) );
	}

	template<class T>
	CAT_INLINE T *AcquireTrailing(u32 trailing_bytes)
	{
		return reinterpret_cast<T*>( Acquire(sizeof(T) + trailing_bytes) );
	}

	// Returns 0 on failure
	// Resizes the given buffer to a new number of bytes
	virtual void *Resize(void *ptr, u32 bytes) = 0;

	template<class T>
	CAT_INLINE T *ResizeTrailing(T *ptr, u32 trailing_bytes)
	{
		return reinterpret_cast<T*>( Resize(ptr, sizeof(T) + trailing_bytes) );
	}

	// Release a buffer
	// Should not die if pointer is null
	virtual void Release(void *ptr) = 0;

	// Attempt to acquire a number of buffers
	// Returns the number of valid buffers it was able to allocate
	virtual u32 AcquireBatch(BatchSet &set, u32 count, u32 bytes = 0) = 0;

	// Attempt to acquire a number of buffers
	// Returns the number of valid buffers it was able to allocate
	virtual void ReleaseBatch(const BatchSet &batch) = 0;

	// Delete an object calling the destructor and then freeing memory
    template<class T>
    CAT_INLINE void Delete(T *ptr)
    {
		if (ptr)
		{
			ptr->~T();
			Release(ptr);
		}
    }
};


} // namespace cat

#endif // CAT_I_ALLOCATOR_HPP
