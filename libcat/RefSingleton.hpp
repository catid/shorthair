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

#ifndef CAT_REF_SINGLETON_HPP
#define CAT_REF_SINGLETON_HPP

#include <cat/lang/Singleton.hpp>
#include <cat/lang/LinkedLists.hpp>
#include <cat/io/Log.hpp>

namespace cat {


/*
	RefSingleton builds on the Singleton class, to add OnFinalize().

	When the order of finalization matters, RefSingleton objects may call the DependsOn<>();
	function inside of their OnInitialize() member.  This function creates a reference counted
	relationship between the two objects.  Circular references will cause this system to break.

	To declare a RefSingleton in the header file:

		#include <cat/lang/RefSingleton.hpp>

		class Settings : public RefSingleton<Settings>
		{
			bool OnInitialize();
			void OnFinalize();
			// No ctor or dtor

	To define a Refsingleton in the source file:

		CAT_REF_SINGLETON(Settings);

		static Clock *m_clock = 0;

		bool Settings::OnInitialize()
		{
			m_clock = Use<Clock>(); // Add a reference to Clock RefSingleton so order of finalization is correct.

			// Optionally check if Clock initialized successfully
			if (!IsInitialized())
			{
				// No need to return a failure here, this singleton can no longer be successfully initialized
				// since one of its dependencies could not initialize.
			}

			return true;
		}

		void Settings::OnFinalize()
		{
		}

	Just ~10 lines of code to convert an object into a singleton with correct finalization order!
*/


// Internal class
class CAT_EXPORT RefSingletonBase : public SListItem
{
	friend class RefSingletons;

	CAT_NO_COPY(RefSingletonBase);

protected:
	int _final_priority; // shutdown order (lower = sooner)
	bool _init_success; // OnInitialize() return value
	RefSingletonBase *_skip_next; // for merge sort

	template<class S>
	CAT_INLINE void UpdatePriority(Singleton<S> *instance)
	{
		// If initialization failed,
		if (!instance || !instance->IsInitialized())
		{
			// Initialization has failed for this one too
			_init_success = false;
		}
	}

	CAT_INLINE void UpdatePriority(RefSingletonBase *instance)
	{
		// If instance could not be acquired,
		if (!instance)
		{
			_init_success = false;
			return;
		}

		int prio = instance->_final_priority;
		CAT_DEBUG_ENFORCE(prio >= 0) << "Circular dependency detected!  This is not supported!";

		// If their priority will bump mine,
		if (_final_priority <= prio)
		{
			// Make my priority lower
			_final_priority = prio + 1;
		}

		// If initialization failed,
		if (!instance->IsInitialized())
		{
			// Initialization has failed for this one too
			_init_success = false;
		}
	}

protected:
	virtual bool OnInitialize() = 0;
	virtual void OnFinalize() = 0;

public:
	CAT_INLINE RefSingletonBase() {}
	CAT_INLINE virtual ~RefSingletonBase() {}

	CAT_INLINE bool IsInitialized() { return _init_success; }

	static void MergeSort(SListForward &list);
};

// Internal class
class CAT_EXPORT RefSingletonImplBase
{
protected:
	CAT_INLINE void Watch(RefSingletonBase *obj);
};

// Internal class
template<class T>
class RefSingletonImpl : public RefSingletonImplBase
{
	T _instance;
	bool _init;

public:
	CAT_INLINE T *GetRef(Mutex &mutex)
	{
		if (_init) return &_instance;

		AutoMutex lock(mutex);

		if (_init) return &_instance;

		// Initialize the object and record result, allowing Use<> to override
		// NOTE: This way inside OnInitialize() the singleton can check if
		// any dependencies failed with a single IsInitialized() check
		RefSingleton<T> *ptr = &_instance;
		ptr->_final_priority = -1;
		ptr->_init_success = true;
		if (!ptr->OnInitialize()) ptr->_init_success = false;

		// If final priority not set, initialize it to 1
		if (ptr->_final_priority < 0)
			ptr->_final_priority = 1;

		Watch(&_instance);

		CAT_FENCE_COMPILER;

		_init = true;

		return &_instance;
	}
};


// In the H file for the object, derive from this class:
template<class T>
class CAT_EXPORT RefSingleton : public RefSingletonBase
{
	friend class RefSingletonImpl<T>;

protected:
	// Called during initialization
	CAT_INLINE virtual bool OnInitialize() { return true; }

	// Called during finalization
	CAT_INLINE virtual void OnFinalize() {}

	// Call only from OnInitialize() to declare which other RefSingletons are used
	template<class S>
	CAT_INLINE S *Use()
	{
		S *instance = S::ref();

		UpdatePriority(instance);

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

	// Set the final priority to zero so that it is among the first to finalize
	CAT_INLINE void FinalizeFirst()
	{
		_final_priority = 0;
	}
	CAT_INLINE void FinalizeLast()
	{
		_final_priority = 9001; // It's over 9000!
	}

public:
	CAT_INLINE virtual ~RefSingleton<T>() {}

	static T *ref();
};


// Use this alternative form to specify which Mutex object to use
#define CAT_REF_SINGLETON_MUTEX(T, M)	\
	static cat::RefSingletonImpl<T> m_T_rss;	\
	template<> T *RefSingleton<T>::ref() { return m_T_rss.GetRef(M); }

// In the C file for the object, use this macro:
#define CAT_REF_SINGLETON(T)	CAT_REF_SINGLETON_MUTEX(T, GetRefSingletonMutex())


// Internal free function
Mutex CAT_EXPORT &GetRefSingletonMutex();

// Internal class
class CAT_EXPORT RefSingletons : public Singleton<RefSingletons>
{
	friend class RefSingletonImplBase;

	SListForward _active_list;
	typedef SListForward::Iterator<RefSingletonBase> iter;

	bool OnInitialize();
	void OnFinalize();

	template<class T>
	CAT_INLINE void Watch(T *obj)
	{
		_active_list.PushFront(obj);
	}

public:
	static void AtExit();
};

// Internal inline member function definition
CAT_INLINE void RefSingletonImplBase::Watch(RefSingletonBase *obj)
{
	RefSingletons::ref()->Watch(obj);
}


} // namespace cat

#endif // CAT_REF_SINGLETON_HPP
