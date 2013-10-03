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

/*
	Based on The Impossibly Fast C++ Delegates by Sergey Ryazanov from
	http://www.codeproject.com/KB/cpp/ImpossiblyFastCppDelegate.aspx (2005)
*/

/*
	Usage:

	Declare a delegate with a void (int) signature, also known as a
	function that returns void and has one parameter that is an int:
		typedef Delegate1<void, int> MyDelegate;
		MyDelegate d;

	Point the delegate to a member function:
		d.SetMember<A, &A::TestFunctionA>(&a);
		d = MyDelegate::FromMember<A, &A::TestFunctionA>(&a);

	Point the delegate to a const member function:
		d.SetConstMember<C, &C::TestFunctionA>(&c);
		d = MyDelegate::FromConstMember<C, &C::TestFunctionA>(&c);

	Point the delegate to a free function:
		d.SetFree<&FreeFunctionX>();
		d = MyDelegate::FromFree<&FreeFunctionX>();

	Invoke the function via the delegate (works for all 3 cases):
		d(1000);

	By default the delegates are uninitialized.
	To clear an array of delegates quickly just zero the memory.

	This implementation is nicer than FastDelegates in my opinion
	because it is simple and easy to read.  It is a little slower
	for virtual functions, but the size of the delegate is small,
	and it will only get better as compilers improve.
*/

#ifndef CAT_DELEGATES_HPP
#define CAT_DELEGATES_HPP

#include <cat/Platform.hpp>

namespace cat {


template <class ret_type>
class Delegate0
{
	typedef ret_type (*StubPointer)(void *);
	typedef Delegate0<ret_type> this_type;

	void *_object;
	StubPointer _stub;

	CAT_INLINE Delegate0(void *object, StubPointer stub)
	{
		_object = object;
		_stub = stub;
	}

	// Stubs

	template <ret_type (*F)()>
	static CAT_INLINE ret_type FreeStub(void *object)
	{
		return (F)();
	}

	template <class T, ret_type (T::*F)()>
	static CAT_INLINE ret_type MemberStub(void *object)
	{
		T *p = static_cast<T*>(object);
		return (p->*F)();
	}

	template <class T, ret_type (T::*F)() const>
	static CAT_INLINE ret_type ConstMemberStub(void *object)
	{
		T *p = static_cast<T*>(object);
		return (p->*F)();
	}

public:
	CAT_INLINE Delegate0() {}

	// Function invocation

	CAT_INLINE ret_type operator()() const
	{
		return (*_stub)(_object);
	}

	// Use stub pointer as a validity flag and equality checker

	CAT_INLINE bool operator==(const this_type &rhs) const
	{
		return _object == rhs._object && _stub == rhs._stub;
	}

	CAT_INLINE bool operator!=(const this_type &rhs) const
	{
		return _object != rhs._object || _stub != rhs._stub;
	}

	CAT_INLINE bool IsValid() const
	{
		return _stub != 0;
	}

	CAT_INLINE bool operator!() const
	{
		return _stub == 0;
	}

	CAT_INLINE void Invalidate()
	{
		_stub = 0;
	}

	// Delegate creation from a function

	template <ret_type (*F)()>
	static CAT_INLINE this_type FromFree()
	{
		return this_type(0, &FreeStub<F>);
	}

	template <class T, ret_type (T::*F)()>
	static CAT_INLINE this_type FromMember(T *object)
	{
		return this_type(object, &MemberStub<T, F>);
	}

	template <class T, ret_type (T::*F)() const>
	static CAT_INLINE this_type FromConstMember(T const *object)
	{
		return this_type(const_cast<T*>( object ), &ConstMemberStub<T, F>);
	}

	// In-place assignment to a different function

	template <ret_type (*F)()>
	CAT_INLINE void SetFree()
	{
		*this = FromFree<F>();
	}

	template <class T, ret_type (T::*F)()>
	CAT_INLINE void SetMember(T *object)
	{
		*this = FromMember<T, F>(object);
	}

	template <class T, ret_type (T::*F)() const>
	CAT_INLINE void SetConstMember(T const *object)
	{
		*this = FromConstMember<T, F>(object);
	}
};


template <class ret_type, class arg1_type>
class Delegate1
{
	typedef ret_type (*StubPointer)(void *, arg1_type);
	typedef Delegate1<ret_type, arg1_type> this_type;

	void *_object;
	StubPointer _stub;

	CAT_INLINE Delegate1(void *object, StubPointer stub)
	{
		_object = object;
		_stub = stub;
	}

	// Stubs

	template <ret_type (*F)(arg1_type)>
	static CAT_INLINE ret_type FreeStub(void *object, arg1_type a1)
	{
		return (F)(a1);
	}

	template <class T, ret_type (T::*F)(arg1_type)>
	static CAT_INLINE ret_type MemberStub(void *object, arg1_type a1)
	{
		T *p = static_cast<T*>(object);
		return (p->*F)(a1);
	}

	template <class T, ret_type (T::*F)(arg1_type) const>
	static CAT_INLINE ret_type ConstMemberStub(void *object, arg1_type a1)
	{
		T *p = static_cast<T*>(object);
		return (p->*F)(a1);
	}

public:
	CAT_INLINE Delegate1() {}

	// Function invocation

	CAT_INLINE ret_type operator()(arg1_type a1) const
	{
		return (*_stub)(_object, a1);
	}

	// Use stub pointer as a validity flag and equality checker

	CAT_INLINE bool operator==(const this_type &rhs) const
	{
		return _object == rhs._object && _stub == rhs._stub;
	}

	CAT_INLINE bool operator!=(const this_type &rhs) const
	{
		return _object != rhs._object || _stub != rhs._stub;
	}

	CAT_INLINE bool IsValid() const
	{
		return _stub != 0;
	}

	CAT_INLINE bool operator!() const
	{
		return _stub == 0;
	}

	CAT_INLINE void Invalidate()
	{
		_stub = 0;
	}

	// Delegate creation from a function

	template <ret_type (*F)(arg1_type)>
	static CAT_INLINE this_type FromFree()
	{
		return this_type(0, &FreeStub<F>);
	}

	template <class T, ret_type (T::*F)(arg1_type)>
	static CAT_INLINE this_type FromMember(T *object)
	{
		return this_type(object, &MemberStub<T, F>);
	}

	template <class T, ret_type (T::*F)(arg1_type) const>
	static CAT_INLINE this_type FromConstMember(T const *object)
	{
		return this_type(const_cast<T*>( object ), &ConstMemberStub<T, F>);
	}

	// In-place assignment to a different function

	template <ret_type (*F)(arg1_type)>
	CAT_INLINE void SetFree()
	{
		*this = FromFree<F>();
	}

	template <class T, ret_type (T::*F)(arg1_type)>
	CAT_INLINE void SetMember(T *object)
	{
		*this = FromMember<T, F>(object);
	}

	template <class T, ret_type (T::*F)(arg1_type) const>
	CAT_INLINE void SetConstMember(T const *object)
	{
		*this = FromConstMember<T, F>(object);
	}
};


template <class ret_type, class arg1_type, class arg2_type>
class Delegate2
{
	typedef ret_type (*StubPointer)(void *, arg1_type, arg2_type);
	typedef Delegate2<ret_type, arg1_type, arg2_type> this_type;

	void *_object;
	StubPointer _stub;

	CAT_INLINE Delegate2(void *object, StubPointer stub)
	{
		_object = object;
		_stub = stub;
	}

	// Stubs

	template <ret_type (*F)(arg1_type, arg2_type)>
	static CAT_INLINE ret_type FreeStub(void *object, arg1_type a1, arg2_type a2)
	{
		return (F)(a1, a2);
	}

	template <class T, ret_type (T::*F)(arg1_type, arg2_type)>
	static CAT_INLINE ret_type MemberStub(void *object, arg1_type a1, arg2_type a2)
	{
		T *p = static_cast<T*>(object);
		return (p->*F)(a1, a2);
	}

	template <class T, ret_type (T::*F)(arg1_type, arg2_type) const>
	static CAT_INLINE ret_type ConstMemberStub(void *object, arg1_type a1, arg2_type a2)
	{
		T *p = static_cast<T*>(object);
		return (p->*F)(a1, a2);
	}

public:
	CAT_INLINE Delegate2() {}

	// Function invocation

	CAT_INLINE ret_type operator()(arg1_type a1, arg2_type a2) const
	{
		return (*_stub)(_object, a1, a2);
	}

	// Use stub pointer as a validity flag and equality checker

	CAT_INLINE bool operator==(const this_type &rhs) const
	{
		return _object == rhs._object && _stub == rhs._stub;
	}

	CAT_INLINE bool operator!=(const this_type &rhs) const
	{
		return _object != rhs._object || _stub != rhs._stub;
	}

	CAT_INLINE bool IsValid() const
	{
		return _stub != 0;
	}

	CAT_INLINE bool operator!() const
	{
		return _stub == 0;
	}

	CAT_INLINE void Invalidate()
	{
		_stub = 0;
	}

	// Delegate creation from a function

	template <ret_type (*F)(arg1_type, arg2_type)>
	static CAT_INLINE this_type FromFree()
	{
		return this_type(0, &FreeStub<F>);
	}

	template <class T, ret_type (T::*F)(arg1_type, arg2_type)>
	static CAT_INLINE this_type FromMember(T *object)
	{
		return this_type(object, &MemberStub<T, F>);
	}

	template <class T, ret_type (T::*F)(arg1_type, arg2_type) const>
	static CAT_INLINE this_type FromConstMember(T const *object)
	{
		return this_type(const_cast<T*>( object ), &ConstMemberStub<T, F>);
	}

	// In-place assignment to a different function

	template <ret_type (*F)(arg1_type, arg2_type)>
	CAT_INLINE void SetFree()
	{
		*this = FromFree<F>();
	}

	template <class T, ret_type (T::*F)(arg1_type, arg2_type)>
	CAT_INLINE void SetMember(T *object)
	{
		*this = FromMember<T, F>(object);
	}

	template <class T, ret_type (T::*F)(arg1_type, arg2_type) const>
	CAT_INLINE void SetConstMember(T const *object)
	{
		*this = FromConstMember<T, F>(object);
	}
};


template <class ret_type, class arg1_type, class arg2_type, class arg3_type>
class Delegate3
{
	typedef ret_type (*StubPointer)(void *, arg1_type, arg2_type, arg3_type);
	typedef Delegate3<ret_type, arg1_type, arg2_type, arg3_type> this_type;

	void *_object;
	StubPointer _stub;

	CAT_INLINE Delegate3(void *object, StubPointer stub)
	{
		_object = object;
		_stub = stub;
	}

	// Stubs

	template <ret_type (*F)(arg1_type, arg2_type, arg3_type)>
	static CAT_INLINE ret_type FreeStub(void *object, arg1_type a1, arg2_type a2, arg3_type a3)
	{
		return (F)(a1, a2, a3);
	}

	template <class T, ret_type (T::*F)(arg1_type, arg2_type, arg3_type)>
	static CAT_INLINE ret_type MemberStub(void *object, arg1_type a1, arg2_type a2, arg3_type a3)
	{
		T *p = static_cast<T*>(object);
		return (p->*F)(a1, a2, a3);
	}

	template <class T, ret_type (T::*F)(arg1_type, arg2_type, arg3_type) const>
	static CAT_INLINE ret_type ConstMemberStub(void *object, arg1_type a1, arg2_type a2, arg3_type a3)
	{
		T *p = static_cast<T*>(object);
		return (p->*F)(a1, a2, a3);
	}

public:
	CAT_INLINE Delegate3() {}

	// Function invocation

	CAT_INLINE ret_type operator()(arg1_type a1, arg2_type a2, arg3_type a3) const
	{
		return (*_stub)(_object, a1, a2, a3);
	}

	// Use stub pointer as a validity flag and equality checker

	CAT_INLINE bool operator==(const this_type &rhs) const
	{
		return _object == rhs._object && _stub == rhs._stub;
	}

	CAT_INLINE bool operator!=(const this_type &rhs) const
	{
		return _object != rhs._object || _stub != rhs._stub;
	}

	CAT_INLINE bool IsValid() const
	{
		return _stub != 0;
	}

	CAT_INLINE bool operator!() const
	{
		return _stub == 0;
	}

	CAT_INLINE void Invalidate()
	{
		_stub = 0;
	}

	// Delegate creation from a function

	template <ret_type (*F)(arg1_type, arg2_type, arg3_type)>
	static CAT_INLINE this_type FromFree()
	{
		return this_type(0, &FreeStub<F>);
	}

	template <class T, ret_type (T::*F)(arg1_type, arg2_type, arg3_type)>
	static CAT_INLINE this_type FromMember(T *object)
	{
		return this_type(object, &MemberStub<T, F>);
	}

	template <class T, ret_type (T::*F)(arg1_type, arg2_type, arg3_type) const>
	static CAT_INLINE this_type FromConstMember(T const *object)
	{
		return this_type(const_cast<T*>( object ), &ConstMemberStub<T, F>);
	}

	// In-place assignment to a different function

	template <ret_type (*F)(arg1_type, arg2_type, arg3_type)>
	CAT_INLINE void SetFree()
	{
		*this = FromFree<F>();
	}

	template <class T, ret_type (T::*F)(arg1_type, arg2_type, arg3_type)>
	CAT_INLINE void SetMember(T *object)
	{
		*this = FromMember<T, F>(object);
	}

	template <class T, ret_type (T::*F)(arg1_type, arg2_type, arg3_type) const>
	CAT_INLINE void SetConstMember(T const *object)
	{
		*this = FromConstMember<T, F>(object);
	}
};

// Add more here if needed, but keep in mind that a short, simple interface
// is rewarded by making the delegates faster...


} // namespace cat

#endif // CAT_DELEGATES_HPP
