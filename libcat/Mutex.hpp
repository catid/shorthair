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

#ifndef CAT_MUTEX_HPP
#define CAT_MUTEX_HPP

#include "Platform.hpp"

#if !defined(CAT_OS_WINDOWS)
# include <pthread.h>
#endif

namespace cat {


// Implements a mutex that is NOT reentrant (for speed)
class CAT_EXPORT Mutex
{
#if defined(CAT_OS_WINDOWS)
    CRITICAL_SECTION cs;
#else
	int init_failure;
	pthread_mutex_t mx;
#endif

public:
    Mutex();
    ~Mutex();

	bool Valid();

    CAT_INLINE bool Enter();
    CAT_INLINE bool Leave();
};


CAT_INLINE bool Mutex::Enter()
{
#if defined(CAT_OS_WINDOWS)

	CAT_FENCE_COMPILER

	EnterCriticalSection(&cs);

	CAT_FENCE_COMPILER

	return true;

#else

	if (init_failure) return false;

	CAT_FENCE_COMPILER

	bool result = pthread_mutex_lock(&mx) == 0;

	CAT_FENCE_COMPILER

	return result;

#endif
}

CAT_INLINE bool Mutex::Leave()
{
#if defined(CAT_OS_WINDOWS)

	CAT_FENCE_COMPILER

	LeaveCriticalSection(&cs);

	CAT_FENCE_COMPILER

	return true;

#else

	if (init_failure) return false;

	CAT_FENCE_COMPILER

	bool result = pthread_mutex_unlock(&mx) == 0;

	CAT_FENCE_COMPILER

	return result;

#endif
}


// RAII Mutex wrapper
class AutoMutex
{
	Mutex *_mutex;

public:
	CAT_INLINE AutoMutex()
	{
		_mutex = 0;
	}

	CAT_INLINE AutoMutex(Mutex &mutex)
	{
		_mutex = &mutex;
		mutex.Enter();
	}

	CAT_INLINE ~AutoMutex()
	{
		Release();
	}

	// TryEnter can be used to hold a lock conditionally
	// through a complex routine and release it at the
	// end only if it was held at some point.
	CAT_INLINE void TryEnter(Mutex &mutex)
	{
		if (!_mutex)
		{
			_mutex = &mutex;
			mutex.Enter();
		}
	}

	CAT_INLINE bool Release()
	{
		bool success = false;

		if (_mutex)
		{
			success = _mutex->Leave();
			_mutex = 0;
		}

		return success;
	}
};


} // namespace cat

#endif // CAT_MUTEX_HPP
