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

#ifndef CAT_HASH_TABLE_HPP
#define CAT_HASH_TABLE_HPP

#include <cat/lang/Strings.hpp>
#include <cat/lang/LinkedLists.hpp>
#include <cat/lang/MergeSort.hpp>

namespace cat {


static const int MAX_HASH_KEY_CHARS = 256;


//// Free functions

int SanitizeKeyStringCase(const char *key, /*char *sanitized_string,*/ char *case_string);
int SanitizeKeyString(const char *key, char *sanitized_string);
int SanitizeKeyRangeString(const char *key, int len, char *sanitized_string);


//// SanitizedKey

class CAT_EXPORT SanitizedKey
{
	char _key[MAX_HASH_KEY_CHARS+1];
	int _len;
	u32 _hash;

public:
	SanitizedKey(const char *key);
	SanitizedKey(const char *key, int len);

	CAT_INLINE u32 Hash() const { return _hash; }
	CAT_INLINE const char *Key() const { return _key; }
	CAT_INLINE int Length() const { return _len; }
};


//// KeyAdapter

class CAT_EXPORT KeyAdapter
{
	const char *_key;
	int _len;
	u32 _hash;

public:
	CAT_INLINE KeyAdapter::KeyAdapter(SanitizedKey &key)
	{
		_key = key.Key();
		_len = key.Length();
		_hash = key.Hash();
	}

	CAT_INLINE KeyAdapter(const char *key, int len, u32 hash)
	{
		_key = key;
		_len = len;
		_hash = hash;
	}

	CAT_INLINE u32 Hash() const { return _hash; }
	CAT_INLINE const char *Key() const { return _key; }
	CAT_INLINE int Length() const { return _len; }
};


//// HashKey

class CAT_EXPORT HashKey
{
protected:
	NulTermFixedStr<MAX_HASH_KEY_CHARS> _key;
	int _len;
	u32 _hash;

public:
	HashKey(const KeyAdapter &key);
	//CAT_INLINE virtual ~HashKey() {}

	CAT_INLINE const char *Key() { return _key; }
	CAT_INLINE int Length() { return _len; }
	CAT_INLINE u32 Hash() { return _hash; }

	CAT_INLINE bool operator==(const KeyAdapter &key)
	{
		return _hash == key.Hash() &&
			   _len == key.Length() &&
			   memcmp(_key, key.Key(), _len) == 0;
	}
};


//// HashValue

class CAT_EXPORT HashValue
{
protected:
	NulTermFixedStr<MAX_HASH_KEY_CHARS> _value;

public:
	CAT_INLINE HashValue() {}
	HashValue(const char *key, int len);
	//CAT_INLINE virtual ~HashValue() {}

	CAT_INLINE void ClearValue() { _value.Clear(); }

	CAT_INLINE int GetValueInt() { return atoi(_value); }

	CAT_INLINE const char *GetValueStr() { return _value; }

	CAT_INLINE void SetValueRangeStr(const char *value, int len)
	{
		_value.SetFromRangeString(value, len);
	}

	CAT_INLINE void SetValueStr(const char *value)
	{
		_value.SetFromNulTerminatedString(value);
	}

	CAT_INLINE void SetValueInt(int ivalue)
	{
		_value.SetFromInteger(ivalue);
	}
};


//// HashItem

class CAT_EXPORT HashItem : public HashKey, public HashValue, public SListItem, public SortableItem<HashItem, u32>
{
	friend class HashTableBase;

public:
	HashItem(const KeyAdapter &key);
	//CAT_INLINE virtual ~HashItem() {}

	template<class T>
	CAT_INLINE void Unwrap(T *&to)
	{
		to = static_cast<T*>( this );
	}
};


//// HashTable

class CAT_EXPORT HashTableBase
{
	friend class Iterator;

	CAT_NO_COPY(HashTableBase);

	static const u32 PREALLOC = 64;
	static const u32 GROW_THRESH = 2;
	static const u32 GROW_RATE = 2;

	u32 _allocated, _used;
	SListForward *_buckets;
	typedef SListForward::Iterator<HashItem> iter;

	bool Grow();

protected:
	CAT_INLINE virtual HashItem *Allocate(const KeyAdapter &key)
	{
		return new HashItem(key);
	}

public:
	HashTableBase();
	~HashTableBase();

	HashItem *Lookup(const KeyAdapter &key); // Returns 0 if key not found
	HashItem *Create(const KeyAdapter &key); // Creates if it does not exist yet

	// Iterator
	class CAT_EXPORT Iterator
	{
		u32 _remaining;
		SListForward *_bucket;
		iter _ii;

		void IterateNext();

	public:
		Iterator(HashTableBase &head);

		CAT_INLINE operator HashItem *()
		{
			return _ii;
		}

		CAT_INLINE HashItem *operator->()
		{
			return _ii;
		}

		CAT_INLINE Iterator &operator++() // pre-increment
		{
			IterateNext();
			return *this;
		}

		CAT_INLINE Iterator &operator++(int) // post-increment
		{
			return ++*this;
		}
	};
};

template<class T>
class CAT_EXPORT HashTable : protected HashTableBase
{
	CAT_NO_COPY(HashTable);

	CAT_INLINE HashItem *Allocate(const KeyAdapter &key)
	{
		return new T(key);
	}

public:
	CAT_INLINE HashTable() {}
	CAT_INLINE ~HashTable() {}

	CAT_INLINE T *Lookup(const KeyAdapter &key)
	{
		return static_cast<T*>( HashTableBase::Lookup(key) );
	}

	CAT_INLINE T *Create(const KeyAdapter &key)
	{
		return static_cast<T*>( HashTableBase::Create(key) );
	}
};


} // namespace cat

#endif // CAT_HASH_TABLE_HPP
