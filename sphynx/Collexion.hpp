/*
	Copyright (c) 2009-2012 Christopher A. Taylor.  All rights reserved.

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

#ifndef CAT_SPHYNX_COLLEXION_HPP
#define CAT_SPHYNX_COLLEXION_HPP

#include <cat/threads/Mutex.hpp>
#include <cat/sphynx/Connexion.hpp>

namespace cat {


namespace sphynx {


/*
	Since the number of clients may be in the thousands, I feel it is
	important to scale effectively.  So in the Collexion data structure,
	insertion and removal are O(1) operations.  Also locks should be held
	for the smallest amount of time possible, so I have taken care to make
	locks short and reduce the amount of locking.  For example, the iterator
	caches large blocks of data instead of locking for each iteration.

	The design is optimized for cache usage, re-using common code to benefit
	from code cache and allocating and accessing table entries on cache line
	boundaries to double memory performance over a naive approach.
*/


//// IConnexionCriterion

// Interface base class for a connexion match criterion
template<class T>
class IConnexionCriterion
{
public:
	// Returns true if the Connexion is a member of the set
	virtual bool In(T *conn) = 0;
};

template<class T>
class AnyConnexion : public IConnexionCriterion<T>
{
public:
	CAT_INLINE bool In(T *conn) { return true; }
};


//// ConnexionSubset

class ConnexionSubset
{
	static const int MIN_ALLOC = 16;

	Connexion **_list;
	int _used, _alloc;

	bool DoubleTable()
	{
		// Calculate new allocation size
		int new_alloc = _alloc * 2;
		if (new_alloc < MIN_ALLOC) new_alloc = MIN_ALLOC;

		// Allocate new list
		Connexion **new_list = new Connexion*[new_alloc];
		if (!new_list) return false;

		// If old elements must be copied,
		if (_list)
		{
			// Copy old list over
			memcpy(new_list, _list, _alloc * sizeof(Connexion*));

			// Free old list
			delete []_list;
		}

		// Update list pointer
		_list = new_list;
		_alloc = new_alloc;
		return true;
	}

public:
	ConnexionSubset()
	{
		_list = 0;
		_alloc = 0;
		_used = 0;
	}
	~ConnexionSubset()
	{
		if (_list) delete []_list;
	}

	// Clear list without deallocating memory
	void Clear()
	{
		_used = 0;
	}

	// Insert a new Connexion into the subset
	void Insert(Connexion *conn)
	{
		// If list must grow,
		if (_used >= _alloc)
			DoubleTable();

		// Insert element
		_list[_used++] = conn;
	}

	CAT_INLINE int Count() { return _used; }

	CAT_INLINE Connexion *operator[](int index) { return _list[index]; }
};


//// BinnedConnexionSubset

class BinnedConnexionSubset
{
	int _worker_count;
	ConnexionSubset *_workers;
	int _count;

public:
	BinnedConnexionSubset()
	{
		_worker_count = WorkerThreads::ref()->GetWorkerCount();

		_workers = new ConnexionSubset[_worker_count];

		_count = 0;
	}

	~BinnedConnexionSubset()
	{
		if (_workers)
			delete []_workers;
	}

	void Clear()
	{
		for (int ii = 0, count = _worker_count; ii < count; ++ii)
		{
			_workers[ii].Clear();
		}

		_count = 0;
	}

	void Insert(Connexion *conn);

	CAT_INLINE int Count() { return _count; }

	CAT_INLINE int WorkerCount() { return _worker_count; }

	CAT_INLINE ConnexionSubset &operator[](int index) { return _workers[index]; }
};


//// Collexion

template<class T>
struct CollexionElement
{
	// Bitfield:
	//  1 bit: COLLISION FLAG
	//  1 bit: KILL FLAG
	//  30 bits: Table index to next element in list + 1
	u32 next;

	// Data at this table element
	T *conn;
};

struct CollexionElement2
{
	// Previous table element in list + 1
	u32 prev;

	// Hash of data pointer from main entry (so it doesn't need to be recalculated during growth)
	u32 hash;
};

template<class T>
class Collexion
{
	static const u32 COLLIDE_MASK = 0x80000000;
	static const u32 KILL_MASK = 0x40000000;
	static const u32 NEXT_MASK = 0x3fffffff;
	static const u32 MIN_ALLOCATED = 32;

	static const u32 MAX_DEFER_RELEASE = 64;

	// Number of used/allocated table elements
	u32 _used, _allocated;

	// First table index in list of active elements
	u32 _active_head;

	// First table index in list of deactivated elements
	// These elements are waiting for set references to go to zero to release element references
	u32 _inactive_head;

	// Number of outstanding references to entire set
	u32 _reference_count;

	// Primary table
	CollexionElement<T> *_table;

	// Secondary table, split off so that primary table elements will
	// fit on a cache line.  Contains data that is only accessed rarely.
	CollexionElement2 *_table2;

	// Table lock
	Mutex _lock;

	// Attempt to double size of hash table (does not hold lock)
	bool DoubleTable();

	// Hash a pointer to a 32-bit table key
	static CAT_INLINE u32 HashPtr(T *ptr)
	{
		u64 key = 0xBADdecafDEADbeef;

#if defined(CAT_WORD_64)
		key ^= *(u64*)&ptr;
#else
		key ^= *(u32*)&ptr;
#endif

		key = (~key) + (key << 18);
		key = key ^ (key >> 31);
		key = key * 21;
		key = key ^ (key >> 11);
		key = key + (key << 6);
		key = key ^ (key >> 22);
		return (u32)key;
	}

	// Unlink an active table key
	void UnlinkActive(u32 key);

	// Inactivate an active table key
	void Inactivate(u32 key);

	// Release entire inactive list
	int ReleaseInactive(T **defer_release_list);

public:
	// Ctor zeros everything
	Collexion();

	// Dtor releases dangling memory
	~Collexion();

	// Release dangling references
	void Cleanup();

	// Insert Connexion object, return false if already present or out of memory
	bool Insert(T *conn);

	// Remove Connexion object from list if it exists
	bool Remove(T *conn);

	// Extract a subset of the listed Connexion objects that match the search criterion
	// Returns the number of elements that matched
	int SubsetAcquire(ConnexionSubset &subset, IConnexionCriterion<T> *criterion = &AnyConnexion());
	int BinnedSubsetAcquire(BinnedConnexionSubset &subset, IConnexionCriterion<T> *criterion = &AnyConnexion<T>());

	// Call this when finished using a subset to release references
	void SubsetRelease();
};


//// Collexion

template<class T>
Collexion<T>::Collexion()
{
	_active_head = 0;
	_inactive_head = 0;
	_used = 0;
	_allocated = 0;
	_table = 0;
	_table2 = 0;
	_reference_count = 0;
}

template<class T>
Collexion<T>::~Collexion()
{
	Cleanup();
}

template<class T>
void Collexion<T>::Cleanup()
{
	StdAllocator *allocator = StdAllocator::ref();

	// If second table exists, free memory
	if (_table2) allocator->Release(_table2);
	_table2 = 0;

	// If table doesn't exist, return
	if (!_table) return;

	// For each allocated table entry,
	for (u32 ii = 0; ii < _allocated; ++ii)
	{
		// Get Connexion object
		T *conn = _table[ii].conn;

		// If object is valid, release it
		if (conn) conn->ReleaseRef(CAT_REFOBJECT_TRACE);
	}

	// Release table memory
	allocator->Release(_table);
	_table = 0;
}

template<class T>
bool Collexion<T>::DoubleTable()
{
	u32 new_allocated = _allocated << 1;
	if (new_allocated < MIN_ALLOCATED) new_allocated = MIN_ALLOCATED;

	// Allocate secondary table
	CollexionElement2 *new_table2 = new CollexionElement2[new_allocated];
	if (!new_table2) return false;

	// Allocate primary table
	CollexionElement<T> *new_table = new CollexionElement<T>[new_allocated];
	if (!new_table)
	{
		delete []new_table2;
		return false;
	}

	// Clear just the parts that need to be cleared
	CAT_CLR(new_table, new_allocated * sizeof(CollexionElement<T>));

	// Initialize new heads
	u32 new_active_head = 0, new_inactive_head = 0;

	// If old table exists,
	if (_table && _table2)
	{
		const u32 mask = _allocated - 1;

		// Active list:

		// For each entry in the old table,
		register u32 old_key = _active_head;
		while (old_key)
		{
			CollexionElement<T> *old_element = &_table[old_key];
			u32 hash = _table2[old_key].hash;
			u32 new_key = hash & mask;

			// While collisions occur,
			while (new_table[new_key].conn)
			{
				// Mark collision
				new_table[new_key].next |= COLLIDE_MASK;

				// Walk collision list
				new_key = (new_key * COLLISION_MULTIPLIER + COLLISION_INCREMENTER) & mask;
			}

			// Fill new table element
			new_table[new_key].conn = old_element->conn;
			new_table2[new_key].hash = hash;

			// Link new element to new list
			if (new_active_head)
			{
				new_table[new_key].next |= new_active_head;
				new_table2[new_active_head - 1].prev = new_key;
			}

			// Update the new head
			new_active_head = new_key + 1;

			// Get next old table entry
			old_key = old_element->next & NEXT_MASK;
		}

		// If a new active head was chosen,
		if (new_active_head)
		{
			// Zero head->prev
			new_table2[new_active_head - 1].prev = 0;
		}

		// Inactive list:

		// For each entry in the old table,
		old_key = _inactive_head;
		while (old_key)
		{
			CollexionElement<T> *old_element = &_table[old_key];
			u32 hash = _table2[old_key].hash;
			u32 new_key = hash & mask;

			// While collisions occur,
			while (new_table[new_key].conn)
			{
				// Mark collision
				new_table[new_key].next |= COLLIDE_MASK;

				// Walk collision list
				new_key = (new_key * COLLISION_MULTIPLIER + COLLISION_INCREMENTER) & mask;
			}

			// Fill new table element
			new_table[new_key].conn = old_element->conn;
			new_table2[new_key].hash = hash;

			// Link new element to new list
			if (new_inactive_head)
			{
				new_table[new_key].next |= new_inactive_head;
				new_table2[new_inactive_head - 1].prev = new_key;
			}

			// Set kill flag
			new_table[new_key].next |= KILL_MASK;

			// Update the new head
			new_inactive_head = new_key + 1;

			// Get next old table entry
			old_key = old_element->next & NEXT_MASK;
		}

		// If a new inactive head was chosen,
		if (new_inactive_head)
		{
			// Zero head->prev
			new_table2[new_inactive_head - 1].prev = 0;
		}
	} // end if old tables both exist

	// Release any existing tables
	if (_table2) delete []_table2;
	if (_table) delete []_table;

	// Replace with new tables
	_table = new_table;
	_table2 = new_table2;
	_allocated = new_allocated;
	_active_head = new_active_head;
	_inactive_head = new_inactive_head;
	return true;
}

template<class T>
bool Collexion<T>::Insert(T *conn)
{
	u32 hash = HashPtr(conn);

	AutoMutex lock(_lock);

	// If more than half of the table will be used,
	if (_used >= (_allocated >> 1))
	{
		// Double the size of the table (O(1) allocation pattern)
		// Growing pains are softened by careful design
		if (!DoubleTable())
			return false;
	}

	// Mask off high bits to make table key from hash
	const u32 mask = _allocated - 1;
	register u32 key = hash & mask;

	CAT_FOREVER
	{
		// If Connexion object is already in the table,
		T *e_conn = _table[key].conn;
		if (e_conn == conn)
		{
			// Abort here
			return false;
		}

		// If this is where it should write,
		if (e_conn == 0)
		{
			// Insert with this key
			break;
		}

		// If there is a collision for this key,
		u32 next = _table[key].next;
		if (next & COLLIDE_MASK)
		{
			// Keep walking collision list
			key = (key * COLLISION_MULTIPLIER + COLLISION_INCREMENTER) & mask;
		}
		else
		{
			// Mark as a collision
			_table[key].next = next | COLLIDE_MASK;
		}
	}

	// Increment used count
	++_used;

	// Link new element to front of list
	if (_active_head) _table2[_active_head - 1].prev = key + 1;
	_table[key].next = (_table[key].next & COLLIDE_MASK) | _active_head;
	_active_head = key + 1;

	// Fill new element
	_table[key].conn = conn;
	_table2[key].hash = hash;
	_table2[key].prev = 0;

	lock.Release();

	conn->AddRef(CAT_REFOBJECT_TRACE);

	return true;
}

template<class T>
void Collexion<T>::UnlinkActive(u32 key)
{
	// Clear reference
	_table[key].conn = 0;

	// Unlink from active list
	u32 next = _table[key].next & NEXT_MASK;
	u32 prev = _table2[key].prev;

	if (prev) _table[prev-1].next = (_table[prev-1].next & ~NEXT_MASK) | next;
	else _active_head = next;
	if (next) _table2[next-1].prev = prev;

	// If this key was a leaf on a collision wind,
	if (!(_table[key].next & COLLIDE_MASK))
	{
		const u32 mask = _allocated - 1;

		// Walk backwards and clear collision flag where it's no longer needed
		do
		{
			// Go backwards through the collision list one step
			key = ((key + COLLISION_INCRINVERSE) * COLLISION_MULTINVERSE) & mask;

			// Stop where collision list stops
			if (!(_table[key].next & COLLIDE_MASK))
				break;

			// Turn off collision flag for previous entry
			_table[key].next &= ~COLLIDE_MASK;

		} while (!_table[key].conn);
	}

	// Update number of used elements
	--_used;
}

template<class T>
void Collexion<T>::Inactivate(u32 key)
{
	// Unlink from active list
	u32 next = _table[key].next & NEXT_MASK;
	u32 prev = _table2[key].prev;

	if (prev) _table[prev-1].next = (_table[prev-1].next & ~NEXT_MASK) | next;
	else _active_head = next;
	if (next) _table2[next-1].prev = prev;

	// Link element to front of inactive list
	if (_inactive_head) _table2[_inactive_head - 1].prev = key + 1;
	_table[key].next = (_table[key].next & COLLIDE_MASK) | _inactive_head | KILL_MASK;
	_inactive_head = key + 1;

	_table2[key].prev = 0;
}

template<class T>
bool Collexion<T>::Remove(T *conn)
{
	const u32 hash = HashPtr(conn);

	AutoMutex lock(_lock);

	// If table doesn't exist,
	if (_used <= 0) return false;

	// Mask off high bits to make table key from hash
	const u32 mask = _allocated - 1;
	u32 key = hash & mask;

	// While target table entry not found,
	CAT_FOREVER
	{
		// If target was found,
		T *e_conn = _table[key].conn;
		if (e_conn == conn)
		{
			// If no references,
			if (_reference_count == 0)
			{
				// NOTE: Cannot already be inactive

				UnlinkActive(key);

				lock.Release();

				// Release Connexion reference at this point
				conn->ReleaseRef(CAT_REFOBJECT_TRACE);
			}
			else
			{
				// If not already inactive,
				if (!(_table[key].next & KILL_MASK))
				{
					// Add to inactive list
					Inactivate(key);
				}
			}

			// Return success
			return true;
		}

		if (!(_table[key].next & COLLIDE_MASK))
		{
			break; // End of collision list
		}

		// Walk collision list
		key = (key * COLLISION_MULTIPLIER + COLLISION_INCREMENTER) & mask;
	}

	// Return failure: not found
	return false;
}

template<class T>
int Collexion<T>::SubsetAcquire(ConnexionSubset &subset, IConnexionCriterion<T> *criterion)
{
	subset.Clear();

	AutoMutex lock(_lock);

	// For each active item,
	u32 key = _active_head;
	while (key)
	{
		// If Connexion is in the set,
		T *conn = _table[key - 1].conn;
		if (criterion->In(conn))
		{
			// Add it
			subset.Insert(conn);
		}

		// Next element
		key = _table[key - 1].next & NEXT_MASK;
	}

	// If nothing was added,
	int count = subset.Count();
	if (count <= 0) return 0;

	// Increment reference count
	_reference_count++;

	return count;
}

template<class T>
int Collexion<T>::BinnedSubsetAcquire(BinnedConnexionSubset &subset, IConnexionCriterion<T> *criterion)
{
	subset.Clear();

	AutoMutex lock(_lock);

	// For each active item,
	u32 key = _active_head;
	while (key)
	{
		// If Connexion is in the set,
		T *conn = _table[key - 1].conn;
		if (criterion->In(conn))
		{
			// Add it
			subset.Insert(conn);
		}

		// Next element
		key = _table[key - 1].next & NEXT_MASK;
	}

	// If nothing was added,
	int count = subset.Count();
	if (count <= 0) return 0;

	// Increment reference count
	_reference_count++;

	return count;
}

template<class T>
int Collexion<T>::ReleaseInactive(T **defer_release_list)
{
	// For each inactive key,
	u32 count = 0;
	for (u32 next, key = _inactive_head; key; key = next & NEXT_MASK)
	{
		next = _table[--key].next;

		// Release reference
		T *conn = _table[key].conn;

		// If release count is under max,
		if (count < MAX_DEFER_RELEASE)
		{
			// Defer the release
			defer_release_list[count] = conn;
		}
		else
		{
			// Release immediately (unfortunate)
			conn->ReleaseRef(CAT_REFOBJECT_TRACE);
		}

		++count;

		// Clear reference
		_table[key].conn = 0;

		// If this key was part of a collision list,
		if (next & COLLIDE_MASK)
			_table[key].next = COLLIDE_MASK;
		else // End of collision list:
		{
			// Clear next flags
			_table[key].next = 0;

			const u32 mask = _allocated - 1;

			// Walk backwards and clear collision flag where it's no longer needed
			do
			{
				// Go backwards through the collision list one step
				key = ((key + COLLISION_INCRINVERSE) * COLLISION_MULTINVERSE) & mask;

				// Stop where collision list stops
				if (!(_table[key].next & COLLIDE_MASK))
					break;

				// Turn off collision flag for previous entry
				_table[key].next &= ~COLLIDE_MASK;

			} while (!_table[key].conn);
		}
	}

	// Update inactive list
	_inactive_head = 0;
	_used -= count;

	return count < MAX_DEFER_RELEASE ? count : MAX_DEFER_RELEASE;
}

template<class T>
void Collexion<T>::SubsetRelease()
{
	AutoMutex lock(_lock);

	// Decrement reference count
	if (--_reference_count == 0)
	{
		// If elements are waiting to release,
		if (_inactive_head)
		{
			T *defer_release_list[MAX_DEFER_RELEASE];
			int defer_release_count = ReleaseInactive(defer_release_list);

			lock.Release();

			// For each deferred release,
			for (int ii = 0; ii < defer_release_count; ++ii)
			{
				defer_release_list[ii]->ReleaseRef(CAT_REFOBJECT_TRACE);
			}
		}
	}
}


} // namespace sphynx


} // namespace cat

#endif // CAT_SPHYNX_COLLEXION_HPP
