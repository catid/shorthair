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

#include <cat/lang/HashTable.hpp>
using namespace cat;


//// Free functions

int cat::SanitizeKeyStringCase(const char *key, /*char *sanitized_string,*/ char *case_string)
{
	char ch, /* *outs = sanitized_string,*/ *outc = case_string;
	bool seen_punct = false;

	while ((ch = *key++))
	{
		if (ch >= 'A' && ch <= 'Z')
		{
			if (seen_punct)
			{
				//*outs++ = '.';
				*outc++ = '.';
				seen_punct = false;
			}
			*outc++ = ch;
			//*outs++ = ch + 'a' - 'A';
		}
		else if (ch >= 'a' && ch <= 'z' ||
			ch >= '0' && ch <= '9')
		{
			if (seen_punct)
			{
				//*outs++ = '.';
				*outc++ = '.';
				seen_punct = false;
			}
			*outc++ = ch;
			//*outs++ = ch;
		}
		else
		{
			if (outc != case_string)
				seen_punct = true;
		}
	}

	*outc = '\0';
	//*outs = '\0';

	return (int)(outc - case_string);
}

int cat::SanitizeKeyString(const char *key, char *sanitized_string)
{
	char ch, *outs = sanitized_string;
	bool seen_punct = false;

	while ((ch = *key++))
	{
		if (ch >= 'A' && ch <= 'Z')
		{
			if (seen_punct)
			{
				*outs++ = '.';
				seen_punct = false;
			}
			*outs++ = ch + 'a' - 'A';
		}
		else if (ch >= 'a' && ch <= 'z' ||
			ch >= '0' && ch <= '9')
		{
			if (seen_punct)
			{
				*outs++ = '.';
				seen_punct = false;
			}
			*outs++ = ch;
		}
		else
		{
			if (outs != sanitized_string)
				seen_punct = true;
		}
	}

	*outs = '\0';

	return (int)(outs - sanitized_string);
}

int cat::SanitizeKeyRangeString(const char *key, int len, char *sanitized_string)
{
	char ch, *outs = sanitized_string;
	bool seen_punct = false;

	while (len-- > 0)
	{
		ch = *key++;

		if (ch >= 'A' && ch <= 'Z')
		{
			if (seen_punct)
			{
				*outs++ = '.';
				seen_punct = false;
			}
			*outs++ = ch + 'a' - 'A';
		}
		else if (ch >= 'a' && ch <= 'z' ||
			ch >= '0' && ch <= '9')
		{
			if (seen_punct)
			{
				*outs++ = '.';
				seen_punct = false;
			}
			*outs++ = ch;
		}
		else
		{
			if (outs != sanitized_string)
				seen_punct = true;
		}
	}

	*outs = '\0';

	return (int)(outs - sanitized_string);
}


//// SanitizedKey

SanitizedKey::SanitizedKey(const char *key)
{
	_len = SanitizeKeyString(key, _key);
	_hash = MurmurHash(_key, _len).Get32();
}

SanitizedKey::SanitizedKey(const char *key, int len)
{
	_len = SanitizeKeyRangeString(key, len, _key);
	_hash = MurmurHash(_key, _len).Get32();
}


//// HashKey

HashKey::HashKey(const KeyAdapter &key)
{
	int len = key.Length();

	_key.SetFromRangeString(key.Key(), len);
	_hash = key.Hash();
	_len = len;
}


//// HashValue

HashValue::HashValue(const char *value, int len)
{
	_value.SetFromRangeString(value, len);
}


//// HashItem

HashItem::HashItem(const KeyAdapter &key)
	: HashKey(key)
{
}


//// HashTableBase

bool HashTableBase::Grow()
{
	// Calculate growth rate
	u32 old_size = _allocated;
	u32 new_size = old_size * GROW_RATE;
	if (new_size < PREALLOC) new_size = PREALLOC;

	CAT_INANE("HashTable") << "Growing to " << new_size << " buckets";

	// Allocate larger bucket array
	SListForward *new_buckets = new (std::nothrow) SListForward[new_size];
	if (!new_buckets) return false;

	if (_buckets)
	{
		// For each bucket,
		u32 mask = new_size - 1;
		for (u32 jj = 0; jj < old_size; ++jj)
		{
			// For each bucket item,
			for (iter ii = _buckets[jj]; ii; ++ii)
			{
				new_buckets[ii->Hash() & mask].PushFront(ii);
			}
		}

		// Free old array
		delete []_buckets;
	}

	_buckets = new_buckets;
	_allocated = new_size;

	return true;
}

HashTableBase::HashTableBase()
{
	_buckets = 0;
	_allocated = 0;
	_used = 0;
}

HashTableBase::~HashTableBase()
{
	// If any buckets are allocated,
	if (_buckets)
	{
		// For each allocated bucket,
		for (u32 ii = 0; ii < _allocated; ++ii)
		{
			SListForward &bucket = _buckets[ii];

			// If bucket is not empty,
			if (!bucket.Empty())
			{
				// For each item in the bucket,
				for (iter ii = bucket; ii; ++ii)
				{
					// Free item
					delete ii;
				}
			}
		}

		// Free the array
		delete []_buckets;
	}
}

HashItem *HashTableBase::Lookup(const KeyAdapter &key)
{
	// If nothing allocated,
	if (!_allocated) return 0;

	// Search used table indices after hash
	u32 ii = key.Hash() & (_allocated - 1);

	// For each item in the selected bucket,
	for (iter jj = _buckets[ii]; jj; ++jj)
	{
		// If the key matches,
		if (*jj == key)
		{
			// Found it!
			return jj;
		}
	}

	return 0;
}

HashItem *HashTableBase::Create(const KeyAdapter &key)
{
	// If first allocation fails,
	if (!_buckets && !Grow()) return 0;

	// If cannot create an item,
	HashItem *item = Allocate(key);
	if (!item) return 0;

	// If time to grow,
	if (_used * GROW_THRESH >= _allocated)
	{
		// If grow fails,
		if (!Grow())
		{
			delete item;
			return 0;
		}
	}

	// Insert in bucket corresponding to hash low bits
	u32 bucket_index = key.Hash() & (_allocated - 1);
	_buckets[bucket_index].PushFront(item);

	// Increment used count to keep track of when to grow
	++_used;

	return item;
}


//// HashTableBase::Iterator

void HashTableBase::Iterator::IterateNext()
{
	if (_ii)
	{
		++_ii;

		if (_ii) return;
	}

	while (_remaining)
	{
		--_remaining;
		++_bucket;

		_ii = *_bucket;

		if (_ii) return;
	}
}

HashTableBase::Iterator::Iterator(HashTableBase &head)
{
	_remaining = head._allocated;
	_bucket = head._buckets;
	_ii = *_bucket;

	if (!_ii)
	{
		IterateNext();
	}
}
