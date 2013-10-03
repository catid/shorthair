/*
	Copyright (c) 2011 Christopher A. Taylor.  All rights reserved.

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

#ifndef CAT_SINGLETON_HPP
#define CAT_SINGLETON_HPP

/*
	This implementation of singletons is motivated by a few real requirements:

	+ Objects that are global,
		but have initialization that must be done once in a thread-safe manner.
	+ Use is initialization, so the client does not need to explicitly initialize.
	+ Pre-allocate the objects in the data section, and initialize at runtime.
	+ Cannot create or copy the singleton object in normal ways.
	+ Easier to type than coding it in a broken way.
	+ Access the object across DLLs without memory allocation issues.
	+ Uses a single global mutex to reduce OS resource overhead.

	Usage:

		To declare a singleton class:

			class SystemInfo : Singleton<SystemInfo>
			{
				bool OnInitialize(); // optional

				...

		To define a singleton class:

			CAT_SINGLETON(SystemInfo);

			static Clock *m_clock = 0;

			bool SystemInfo::OnInitialize() // optional
			{
				Use(m_clock); // Use the Clock singleton
				//m_clock = Use<Clock>(); // Alternative way, also returns a pointer to Clock

				// Optionally check if Clock initialized successfully
				if (!IsInitialized())
				{
					// No need to return a failure here, this singleton can no longer be successfully initialized
					// since one of its dependencies could not initialize.
				}

				return true;
			}

		To access a member of the singleton instance:

			MyClass::ref()->blah

	Some things it won't do and work-arounds:

	- You cannot specify a deconstructor for the object.
		-> Use RefObjects for singletons that need cleanup.
*/

#include <cat/threads/Mutex.hpp>

namespace cat {


// Internal class
template<class T>
class SingletonImpl
{
	T _instance;
	bool _init;

public:
	CAT_INLINE T *GetRef(Mutex &mutex)
	{
		if (_init) return &_instance;

		AutoMutex lock(mutex);

		if (_init) return &_instance;

		Singleton<T> *ptr = &_instance;
		ptr->_init_success = true;
		if (!ptr->OnInitialize()) ptr->_init_success = false;

		CAT_FENCE_COMPILER;

		_init = true;

		return &_instance;
	}
};


// In the H file for the object, derive from this class:
template<class T>
class CAT_EXPORT Singleton
{
	friend class SingletonImpl<T>;

	CAT_NO_COPY(Singleton);

	bool _init_success;

protected:
	CAT_INLINE Singleton() {}

	// Called during initialization
	CAT_INLINE virtual bool OnInitialize() { return true; }

	// Call only from OnInitialize() to declare which other Singletons are used
	template<class S>
	CAT_INLINE S *Use()
	{
		S *instance = S::ref();

		// If initialization failed,
		if (!instance || !instance->IsInitialized())
		{
			// Initialization has failed for this one too
			_init_success = false;
		}

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

public:
	CAT_INLINE virtual ~Singleton() {}

	// Call to check return code of initialization
	CAT_INLINE bool IsInitialized() { return _init_success; }

	static T *ref();
};


// Use this alternative form to specify which Mutex object to use
#define CAT_SINGLETON_MUTEX(T, M)			\
	static cat::SingletonImpl<T> m_T_ss;	\
	template<> T *Singleton<T>::ref() { return m_T_ss.GetRef(M); }

// In the C file for the object, use this macro:
#define CAT_SINGLETON(T)	CAT_SINGLETON_MUTEX(T, GetSingletonMutex())


// Internal free function
Mutex CAT_EXPORT &GetSingletonMutex();


} // namespace cat

#endif // CAT_SINGLETON_HPP
