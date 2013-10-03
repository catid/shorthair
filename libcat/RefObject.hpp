/*
	Copyright (c) 2009-2011 Christopher A. Taylor.  All rights reserved.

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

#ifndef CAT_REF_OBJECT_HPP
#define CAT_REF_OBJECT_HPP

#include <cat/threads/Atomic.hpp>
#include <cat/threads/WaitableFlag.hpp>
#include <cat/threads/Mutex.hpp>
#include <cat/threads/Thread.hpp>
#include <cat/lang/LinkedLists.hpp>
#include <cat/lang/RefSingleton.hpp>

#if !defined(CAT_TRACE_REFOBJECT) && defined(CAT_DEBUG)
#define CAT_TRACE_REFOBJECT
#endif

#if defined(CAT_TRACE_REFOBJECT)
#include <cat/io/Log.hpp>
#endif

#if defined(CAT_NO_ATOMIC_ADD) || defined(CAT_NO_ATOMIC_SET)
#define CAT_NO_ATOMIC_REF_OBJECT
#endif

#if defined(CAT_TRACE_REFOBJECT)
#define CAT_REFOBJECT_TRACE CAT_FILE_LINE_STRING "@" CAT_FUNCTION
#else
#define CAT_REFOBJECT_TRACE 0
#endif

namespace cat {


class RefObject;
class RefObjects;


// Mechanism to wait for reference-counted objects to finish shutting down
class CAT_EXPORT RefObjects : Thread, public RefSingleton<RefObjects>
{
	friend class RefObject;

	bool OnInitialize();
	void OnFinalize();

	DListForward _active_list, _dead_list;
	typedef DListForward::Iterator<RefObject> iter;

	bool _shutdown;
	WaitableFlag _shutdown_flag;

	void Kill(RefObject *obj);
	void BuryDeadites();
	bool Entrypoint(void *param);

	// NOTE: Will delete and nullify object if it fails to initialize
	bool Watch(const char *file_line, RefObject *obj);

public:
	// Acquire a RefObject with a default constructor
	template<class T>
	static T *Create(const char *file_line, T *&obj)
	{
		obj = new (std::nothrow) T;

		if (obj && !RefObjects::ref()->Watch(file_line, obj))
			obj = 0;

		return obj;
	}

	// Alternative way
	template<class T>
	static T *Create(const char *file_line)
	{
		T *obj = new (std::nothrow) T;

		if (obj && !RefObjects::ref()->Watch(file_line, obj))
			obj = 0;

		return obj;
	}
};


// Classes that derive from RefObject have asynchronously managed lifetimes
// Never delete a RefObject directly.  Use the Destroy() member instead
class CAT_EXPORT RefObject : DListItem
{
	friend class RefObjects;

	CAT_NO_COPY(RefObject);

#if defined(CAT_NO_ATOMIC_REF_OBJECT)
	Mutex _lock;
#endif

	volatile u32 _ref_count, _shutdown;
	bool _init_success;

	void OnZeroReferences(const char *file_line);

public:
	RefObject();
	CAT_INLINE virtual ~RefObject() {}

	void Destroy(const char *file_line);

	CAT_INLINE bool IsInitialized() { return _init_success; }
	CAT_INLINE bool IsShutdown() { return _shutdown != 0; }

	CAT_INLINE void AddRef(const char *file_line, s32 times = 1)
	{
#if defined(CAT_TRACE_REFOBJECT)
		CAT_WARN("RefObject") << GetRefObjectName() << "#" << this << " add " << times << " at " << file_line;
#endif

#if defined(CAT_NO_ATOMIC_REF_OBJECT)
		_lock.Enter();
		_ref_count += times;
		_lock.Leave();
#else
		// Increment reference count by # of times
		Atomic::Add(&_ref_count, times);
#endif
	}

	CAT_INLINE void ReleaseRef(const char *file_line, s32 times = 1)
	{
#if defined(CAT_TRACE_REFOBJECT)
		CAT_WARN("RefObject") << GetRefObjectName() << "#" << this << " release " << times << " at " << file_line;
#endif

		// Decrement reference count by # of times
		// If all references are gone,
#if defined(CAT_NO_ATOMIC_REF_OBJECT)
		u32 ref_count;

		_lock.Enter();
		ref_count = _ref_count;
		_ref_count -= times;
		_lock.Leave();

		if (ref_count == times)
#else
		if (Atomic::Add(&_ref_count, -times) == times)
#endif
		{
			OnZeroReferences(file_line);
		}
	}

	// Safe release -- If not null, then releases and sets to null
	template<class T>
	static CAT_INLINE void Release(T * &object)
	{
		if (object)
		{
			object->ReleaseRef(CAT_REFOBJECT_TRACE);
			object = 0;
		}
	}

public:
	// Return a C-string naming the derived RefObject uniquely.
	// For debug output; it can be used to report which object is locking up.
	virtual const char *GetRefObjectName() = 0;

protected:
	// Declare usage of another singleton, which will also affect initialization success
	template<class S>
	CAT_INLINE S *Use()
	{
		S *instance = S::ref();

		if (!instance || !instance->IsInitialized())
			_init_success = false;

		return instance;
	}

	// Alternative way to use another singleton
	template<class S>
	CAT_INLINE S *Use(S *&s)
	{
		return (s = Use<S>());
	}
	template<class S0, class S1>
	CAT_INLINE void Use(S0 *&s0, S1 *&s1)
	{
		Use(s0);
		Use(s1);
	}
	template<class S0, class S1, class S2>
	CAT_INLINE void Use(S0 *&s0, S1 *&s1, S2 *&s2)
	{
		Use(s0, s1);
		Use(s2);
	}
	template<class S0, class S1, class S2, class S3>
	CAT_INLINE void Use(S0 *&s0, S1 *&s1, S2 *&s2, S3 *&s3)
	{
		Use(s0, s1);
		Use(s2, s3);
	}
	template<class S0, class S1, class S2, class S3, class S4>
	CAT_INLINE void Use(S0 *&s0, S1 *&s1, S2 *&s2, S3 *&s3, S4 *&s4)
	{
		Use(s0, s1, s2, s3);
		Use(s4);
	}

	// Called when an object is constructed.
	// Allows the object to reference itself on instantiation and report startup
	// errors without putting it in the constructor where it doesn't belong.
	// Return false to delete the object immediately.
	// Especially handy for using RefObjects as a plugin system.
	CAT_INLINE virtual bool OnInitialize() { return true; }

	// Called when a shutdown is in progress.
	// The object should release any internally held references.
	// such as private threads that are working on the object.
	// Always called and before OnFinalize().
	// Proper implementation of derived classes should call the parent version.
	CAT_INLINE virtual void OnDestroy() {}

	// Called when object has no more references.
	// Return true to delete the object.
	// Always called and after OnDestroy().
	CAT_INLINE virtual bool OnFinalize() { return true; }
};


// Auto release for RefObjects
template<class T>
class AutoRelease
{
	T *_ref;

public:
	CAT_INLINE AutoRelease(T *t = 0) throw() { _ref = t; }
	CAT_INLINE ~AutoRelease() throw() { if (_ref) _ref->ReleaseRef(CAT_REFOBJECT_TRACE); }
	CAT_INLINE AutoRelease &operator=(T *t) throw() { Reset(t); return *this; }

	CAT_INLINE T *Get() throw() { return _ref; }
	CAT_INLINE T *operator->() throw() { return _ref; }
	CAT_INLINE T &operator*() throw() { return *_ref; }
	CAT_INLINE operator T*() { return _ref; }

	CAT_INLINE void Forget() throw() { _ref = 0; }
	CAT_INLINE void Reset(T *t = 0) throw() { _ref = t; }
};


// Auto shutdown for RefObjects
template<class T>
class AutoDestroy
{
	T *_ref;

public:
	CAT_INLINE AutoDestroy(T *t = 0) throw() { _ref = t; }
	CAT_INLINE ~AutoDestroy() throw() { if (_ref) _ref->Destroy(CAT_REFOBJECT_TRACE); }
	CAT_INLINE AutoDestroy &operator=(T *t) throw() { Reset(t); return *this; }

	CAT_INLINE T *Get() throw() { return _ref; }
	CAT_INLINE T *operator->() throw() { return _ref; }
	CAT_INLINE T &operator*() throw() { return *_ref; }
	CAT_INLINE operator T*() { return _ref; }

	CAT_INLINE void Forget() throw() { _ref = 0; }
	CAT_INLINE void Reset(T *t = 0) throw() { _ref = t; }
};


} // namespace cat

#endif // CAT_REF_OBJECT_HPP
