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

#ifndef CAT_LINKED_LISTS_HPP
#define CAT_LINKED_LISTS_HPP

#include <cat/Platform.hpp>

/*
	The point of this code is to generate fast and correct implementations of
	linked lists that introduce a minimal amount of overhead.  When applicable
	these designs are way better than std::list as the next/prev pointers are
	stored inside of the objects in the list.

	I was finding that I had to write linked list code over and over and
	decided it was time to write it in a reusable way.
*/

namespace cat {


/*
	Forward-only doubly linked list

	Macros for correct implementation of a linked list,
	where the next/prev variables are members of the objects in
	the list.  The names of the next/prev member variables must
	be provided in the arguments to the macros.

	To iterate through the list, use code like this:

		for (Node *item = head; item; item = item->next)

	Can insert at the head of the list, pushing the previous head
	down the list.

	Can erase an item in the list given a pointer to the item.

	Operations are all O(1).
	Not thread-safe.
*/

/*
	Push object to the front of the list.

	head: Pointer to the head of the list
	obj: Pointer to object that will be inserted at front
	next: Name of member variable pointer to next list item
	prev: Name of member variable pointer to previous list item
*/
#define CAT_FDLL_PUSH_FRONT(head, obj, next, prev)	\
{													\
	(obj)->prev = 0;								\
	(obj)->next = head;								\
													\
	if (head) (head)->prev = obj;					\
													\
	head = obj;										\
}

/*
	Insert an item directly before another item.

	head: Pointer to the head of the list
	obj: Pointer to object that will be inserted before another item
	another: List item that will be after the inserted item
	next: Name of member variable pointer to next list item
	prev: Name of member variable pointer to previous list item
*/
#define CAT_FDLL_INSERT_BEFORE(head, obj, another, next, prev)	\
{																\
	(obj)->prev = (another)->prev;								\
	(obj)->next = another;										\
																\
	if (!(another)->prev) head = obj;							\
																\
	(another)->prev = obj;										\
}

/*
	Insert an item directly after another item.

	head: Pointer to the head of the list
	obj: Pointer to object that will be inserted after another item
	another: List item that will be before the inserted item
	next: Name of member variable pointer to next list item
	prev: Name of member variable pointer to previous list item
*/
#define CAT_FDLL_INSERT_AFTER(head, obj, another, next, prev)	\
{																\
	(obj)->next = (another)->next;								\
	(obj)->prev = another;										\
																\
	(another)->next = obj;										\
}

/*
	Erase object from the list, does not release memory.

	head: Pointer to the head of the list
	obj: Pointer to object that will be inserted at front
	next: Name of member variable pointer to next list item
	prev: Name of member variable pointer to previous list item
*/
#define CAT_FDLL_ERASE(head, obj, next, prev)				\
{															\
	if ((obj)->prev)	((obj)->prev)->next = (obj)->next;	\
	else				head = (obj)->next;					\
															\
	if ((obj)->next)	((obj)->next)->prev = (obj)->prev;	\
}


/*
	Bi-directional doubly linked list

	Macros for correct implementation of a doubly linked list,
	where the next/prev variables are members of the objects in
	the list.  The names of the next/prev member variables must
	be provided in the arguments to the macros.

	To iterate forward through the list, use code like this:

		for (Node *item = head; item; item = item->next)

	To iterate backward through the list, use code like this:

		for (Node *item = tail; item; item = item->prev)

	Can insert at the head of the list, pushing the previous head
	down the list.

	Can insert at the tail of the list, appending to the list.

	Can erase an item in the list given a pointer to the item.

	Operations are all O(1).
	Not thread-safe.
*/

/*
	Push object to the front of the list.

	head: Pointer to the head of the list
	tail: Pointer to the tail of the list
	obj: Pointer to object that will be inserted at front
	next: Name of member variable pointer to next list item
	prev: Name of member variable pointer to previous list item
*/
#define CAT_BDLL_PUSH_FRONT(head, tail, obj, next, prev)	\
{														\
	(obj)->prev = 0;									\
	(obj)->next = head;									\
														\
	if (head)	(head)->prev = obj;						\
	else		tail = obj;								\
														\
	head = obj;											\
}

/*
	Push object to the back of the list, appending to it.

	head: Pointer to the head of the list
	tail: Pointer to the tail of the list
	obj: Pointer to object that will be inserted at front
	next: Name of member variable pointer to next list item
	prev: Name of member variable pointer to previous list item
*/
#define CAT_BDLL_PUSH_BACK(head, tail, obj, next, prev)	\
{														\
	(obj)->prev = tail;									\
	(obj)->next = 0;									\
														\
	if (tail)	(tail)->next = obj;						\
	else		head = obj;								\
														\
	tail = obj;											\
}

/*
	Insert an item directly before another item.

	head: Pointer to the head of the list
	tail: Pointer to the tail of the list
	obj: Pointer to object that will be inserted before another item
	another: List item that will be after the inserted item
	next: Name of member variable pointer to next list item
	prev: Name of member variable pointer to previous list item
*/
#define CAT_BDLL_INSERT_BEFORE(head, tail, obj, another, next, prev)	\
{																\
	(obj)->prev = (another)->prev;								\
	(obj)->next = another;										\
																\
	if (!(another)->prev) head = obj;							\
																\
	(another)->prev = obj;										\
}

/*
	Insert an item directly after another item.

	head: Pointer to the head of the list
	tail: Pointer to the tail of the list
	obj: Pointer to object that will be inserted after another item
	another: List item that will be before the inserted item
	next: Name of member variable pointer to next list item
	prev: Name of member variable pointer to previous list item
*/
#define CAT_BDLL_INSERT_AFTER(head, tail, obj, another, next, prev)	\
{																\
	(obj)->next = (another)->next;								\
	(obj)->prev = another;										\
																\
	if (!(another)->next) tail = obj;							\
																\
	(another)->next = obj;										\
}

/*
	Erase object from the list, does not release memory.

	head: Pointer to the head of the list
	tail: Pointer to the tail of the list
	obj: Pointer to object that will be inserted at front
	next: Name of member variable pointer to next list item
	prev: Name of member variable pointer to previous list item
*/
#define CAT_BDLL_ERASE(head, tail, obj, next, prev)				\
{																\
	if ((obj)->prev)	((obj)->prev)->next = (obj)->next;		\
	else				head = (obj)->next;						\
																\
	if ((obj)->next)	((obj)->next)->prev = (obj)->prev;		\
	else				tail = (obj)->prev;						\
}


/*
	Derive doubly-linked list items from this base class
	to wrap using the macros above.
*/
class CAT_EXPORT DListItem
{
	friend class DList;
	friend class DListForward;
	friend class DListIteratorBase;

protected:
	DListItem *_dl_next, *_dl_prev;
};


// Internal class
class CAT_EXPORT DListIteratorBase
{
protected:
	DListItem *_item, *_next;

public:
	CAT_INLINE DListItem *GetNext()
	{
		DListItem *next = _next;
		if (next) _next = next->_dl_next;
		return next;
	}

	CAT_INLINE DListItem *GetPrev()
	{
		DListItem *prev = _next;
		if (prev) _next = prev->_dl_prev;
		return prev;
	}
};


/*
	Access the linked list through this type.
*/
class CAT_EXPORT DListForward
{
	DListItem *_head;

public:
	CAT_INLINE DListForward()
	{
		Clear();
	}

	CAT_INLINE DListItem *Head() { return _head; }
	CAT_INLINE bool Empty() { return _head == 0; }

	CAT_INLINE void Clear()
	{
		_head = 0;
	}
	CAT_INLINE DListForward &operator=(DListForward &list)
	{
		_head = list._head;
		return *this;
	}
	CAT_INLINE void Steal(DListForward &list)
	{
		_head = list._head;
		list.Clear();
	}

	void PushFront(DListItem *item);
	void InsertBefore(DListItem *item, DListItem *before);
	void InsertAfter(DListItem *item, DListItem *after);
	void Erase(DListItem *item);

	/*
		When iterating forward through the list,
		use the following mechanism:

		typedef DListForward::Iterator<MyObject> iter;

		for (iter ii = list; ii; ++ii)
	*/
	template<class T>
	class Iterator : public DListIteratorBase
	{
	public:
		CAT_INLINE Iterator()
		{
			_item = 0;
		}

		// Initialize to head of list
		CAT_INLINE Iterator(DListForward &list)
		{
			DListItem *item = list._head;

			_item = item;
			if (item) _next = item->_dl_next;
		}
		CAT_INLINE Iterator &operator=(DListForward &list)
		{
			DListItem *item = list._head;

			_item = item;
			if (item) _next = item->_dl_next;
			return *this;
		}

		// Initialize to an arbitrary position in the list
		CAT_INLINE Iterator(DListItem *head)
		{
			_item = head;
			if (head) _next = head->_dl_next;
		}
		CAT_INLINE Iterator &operator=(DListItem *head)
		{
			_item = head;
			if (head) _next = head->_dl_next;
			return *this;
		}

		CAT_INLINE operator T *()
		{
			return static_cast<T*>( _item );
		}

		CAT_INLINE T *GetRef()
		{
			return static_cast<T*>( _item );
		}

		CAT_INLINE T *operator->()
		{
			return static_cast<T*>( _item );
		}

		CAT_INLINE Iterator &operator++() // pre-increment
		{
			_item = GetNext();
			return *this;
		}

		CAT_INLINE Iterator &operator++(int) // post-increment
		{
			return ++*this;
		}
	};
};


/*
	Access the linked list through this type.
*/
class CAT_EXPORT DList
{
	DListItem *_head, *_tail;

public:
	CAT_INLINE DList(DListItem *head, DListItem *tail)
	{
		_head = head;
		_tail = tail;
	}
	CAT_INLINE DList()
	{
		Clear();
	}

	CAT_INLINE DListItem *Head() { return _head; }
	CAT_INLINE DListItem *Tail() { return _tail; }
	CAT_INLINE bool Empty() { return _head == 0; }

	CAT_INLINE void Clear()
	{
		_head = _tail = 0;
	}
	CAT_INLINE DList &operator=(DList &list)
	{
		_head = list._head;
		_tail = list._tail;
		return *this;
	}
	CAT_INLINE void Steal(DList &list)
	{
		_head = list._head;
		_tail = list._tail;
		list.Clear();
	}

	void PushFront(DListItem *item);
	void PushBack(DListItem *item);
	void InsertBefore(DListItem *item, DListItem *before);
	void InsertAfter(DListItem *item, DListItem *after);
	void Erase(DListItem *item);

	// Remove list at and after item from this list, and return what was removed
	DList Chop(DListItem *item);

	/*
		When iterating forward through the list,
		use the following mechanism:

		typedef DList::ForwardIterator<MyObject> iter;

		for (iter ii = list; ii; ++ii)
	*/
	template<class T>
	class ForwardIterator : public DListIteratorBase
	{
	public:
		CAT_INLINE ForwardIterator()
		{
			_item = 0;
		}

		// Set to list head
		CAT_INLINE ForwardIterator(DList &list)
		{
			DListItem *item = list._head;

			_item = item;
			if (item) _next = item->_dl_next;
		}
		CAT_INLINE ForwardIterator &operator=(DList &list)
		{
			DListItem *item = list._head;

			_item = item;
			if (item) _next = item->_dl_next;
			return *this;
		}

		// Set to list item
		CAT_INLINE ForwardIterator(DListItem *item)
		{
			_item = item;
			if (item) _next = item->_dl_next;
		}
		CAT_INLINE ForwardIterator &operator=(DListItem *item)
		{
			_item = item;
			if (item) _next = item->_dl_next;
			return *this;
		}

		CAT_INLINE operator T *()
		{
			return static_cast<T*>( _item );
		}
		CAT_INLINE T *operator->()
		{
			return static_cast<T*>( _item );
		}

		CAT_INLINE ForwardIterator &operator++() // pre-increment
		{
			_item = GetNext();
			return *this;
		}
		CAT_INLINE ForwardIterator &operator++(int) // post-increment
		{
			return ++*this;
		}
	};

	template<class T>
	class BackIterator : public DListIteratorBase
	{
	public:
		CAT_INLINE BackIterator()
		{
			_item = 0;
		}

		// Set to list tail
		CAT_INLINE BackIterator(DList &list)
		{
			DListItem *item = list._tail;

			_item = item;
			if (item) _next = item->_dl_prev;
		}
		CAT_INLINE BackIterator &operator=(DList &list)
		{
			DListItem *item = list._tail;

			_item = item;
			if (item) _next = item->_dl_prev;
			return *this;
		}

		// Set to list item
		CAT_INLINE BackIterator(DListItem *item)
		{
			_item = item;
			if (item) _next = item->_dl_prev;
		}
		CAT_INLINE BackIterator &operator=(DListItem *item)
		{
			_item = item;
			if (item) _next = item->_dl_prev;
			return *this;
		}

		CAT_INLINE operator T *()
		{
			return static_cast<T*>( _item );
		}
		CAT_INLINE T *operator->()
		{
			return static_cast<T*>( _item );
		}

		CAT_INLINE BackIterator &operator--() // pre-decrement
		{
			_item = GetPrev();
			return *this;
		}
		CAT_INLINE BackIterator &operator--(int) // post-decrement
		{
			return --*this;
		}
	};
};


/*
	Forward-only singly linked list

	Macros for correct implementation of a linked list,
	where the next/prev variables are members of the objects in
	the list.  The names of the next/prev member variables must
	be provided in the arguments to the macros.

	To iterate through the list, use code like this:

		for (Node *item = head; item; item = item->next)

	Can insert at the head of the list, pushing the previous head
	down the list.

	Can erase an item in the list given a pointer to the item.

	Operations are all O(1).
	Not thread-safe.
*/

/*
	Push object to the front of the list.

	head: Pointer to the head of the list
	obj: Pointer to object that will be inserted at front
	next: Name of member variable pointer to next list item
	prev: Name of member variable pointer to previous list item
*/
#define CAT_FSLL_PUSH_FRONT(head, obj, next)	\
{												\
	(obj)->next = head;							\
	head = obj;									\
}

/*
	Insert an item directly after another item.

	head: Pointer to the head of the list
	obj: Pointer to object that will be inserted after another item
	another: List item that will be before the inserted item
	next: Name of member variable pointer to next list item
	prev: Name of member variable pointer to previous list item
*/
#define CAT_FSLL_INSERT_AFTER(head, obj, another, next)	\
{														\
	(obj)->next = (another)->next;						\
	(another)->next = obj;								\
}

/*
	Erase object from the list, does not release memory.

	head: Pointer to the head of the list
	obj: Pointer to object that will be erased after another item
	another: Pointer to object before the item to be erased, or 0 for head
	next: Name of member variable pointer to next list item
	prev: Name of member variable pointer to previous list item
*/
#define CAT_FSLL_ERASE_AFTER(head, obj, another, next)	\
{														\
	if (another)	(another)->next = (obj)->next;		\
	else			head = (obj)->next;					\
}


/*
	Derive singly-linked list items from this base class
	to wrap using the macros above.
*/
class CAT_EXPORT SListItem
{
	friend class SListForward;
	friend class SListIteratorBase;

protected:
	SListItem *_sl_next;
};


// Internal class
class CAT_EXPORT SListIteratorBase
{
	friend class SListForward;

protected:
	SListItem *_prev, *_item, *_next;
};


/*
	Access the linked list through this type.
*/
class CAT_EXPORT SListForward
{
	SListItem *_head;

public:
	CAT_INLINE SListForward()
	{
		Clear();
	}

	CAT_INLINE SListItem *Head() { return _head; }
	CAT_INLINE bool Empty() { return _head == 0; }

	CAT_INLINE void Clear()
	{
		_head = 0;
	}
	CAT_INLINE SListForward &operator=(SListForward &list)
	{
		_head = list._head;
		return *this;
	}
	CAT_INLINE SListForward &operator=(SListItem *item)
	{
		_head = item;
		return *this;
	}
	CAT_INLINE void Steal(SListForward &list)
	{
		_head = list._head;
		list.Clear();
	}

	void PushFront(SListItem *item);
	void InsertAfter(SListItem *item, SListItem *after);
	void EraseAfter(SListItem *item, SListItem *after);

	// Erase via iterator to simplify usage
	CAT_INLINE void Erase(SListIteratorBase &iterator)
	{
		EraseAfter(iterator._item, iterator._prev);

		iterator._item = iterator._prev;
	}

	/*
		When iterating forward through the list,
		use the following mechanism:

		typedef SListForward::Iterator<MyObject> iter;

		for (iter ii = list; ii; ++ii)
	*/
	template<class T>
	class Iterator : public SListIteratorBase
	{
	public:
		CAT_INLINE Iterator()
		{
			_item = 0;
		}

		CAT_INLINE Iterator(SListForward &list)
		{
			SListItem *head = list._head;

			_prev = 0;
			_item = head;
			_next = head ? head->_sl_next : 0;
		}
		CAT_INLINE Iterator &operator=(SListForward &list)
		{
			SListItem *head = list._head;

			_prev = 0;
			_item = head;
			_next = head ? head->_sl_next : 0;

			return *this;
		}

		CAT_INLINE operator T *()
		{
			return static_cast<T*>( _item );
		}
		CAT_INLINE T *operator->()
		{
			return static_cast<T*>( _item );
		}

		CAT_INLINE T *GetPrevious()
		{
			return static_cast<T*>( _prev );
		}

		CAT_INLINE Iterator &operator++() // pre-increment
		{
			_prev = _item;
			_item = _next;
			_next = _next ? _next->_sl_next : 0;

			return *this;
		}
		CAT_INLINE Iterator &operator++(int) // post-increment
		{
			return ++*this;
		}
	};
};


} // namespace cat

#endif // CAT_LINKED_LISTS_HPP
