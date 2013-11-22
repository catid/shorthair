/*
	Copyright (c) 2013 Chris Taylor.  All rights reserved.

	Redistribution and use in source and binary forms, with or without
	modification, are permitted provided that the following conditions are met:

	* Redistributions of source code must retain the above copyright notice,
	  this list of conditions and the following disclaimer.
	* Redistributions in binary form must reproduce the above copyright notice,
	  this list of conditions and the following disclaimer in the documentation
	  and/or other materials provided with the distribution.
	* Neither the name of Brook nor the names of its contributors may be used
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

#ifndef SMART_ARRAY_HPP
#define SMART_ARRAY_HPP

#include "Platform.hpp"
#include "Enforcer.hpp"
#include <stdlib.h>

namespace cat {


//// SmartArray

template<class T> class SmartArray {
	static const int ALIGN = 8; // byte alignment

	T *_data;
	int _size, _alloc;

	static T *aligned_malloc(int size) {
		// Allocate memory
		u8 *data = (u8 *)malloc(8 + sizeof(T) * size);

		// Get pointer offset residual
#ifdef CAT_WORD_64
		int offset = (u32)(u64)data & 7;
#else
		int offset = (u32)data & 7;
#endif

		// Bump data pointer up to the next multiple of 8 bytes
		data += 8 - offset;

		// Record the offset right before start of data
		data[-1] = offset;

		return (T *)data;
	}

	// This version uses calloc to initialize the data
	static T *aligned_malloc_zero(int size) {
		// Allocate memory
		u8 *data = (u8 *)calloc(8 + sizeof(T) * size, 1);

		// Get pointer offset residual
#ifdef CAT_WORD_64
		int offset = (u32)(u64)data & 7;
#else
		int offset = (u32)data & 7;
#endif

		// Bump data pointer up to the next multiple of 8 bytes
		data += 8 - offset;

		// Record the offset right before start of data
		data[-1] = offset;

		return (T *)data;
	}

	static void aligned_free(void *data) {
		u8 *orig = (u8 *)data;

		CAT_DEBUG_ENFORCE(orig[-1] < 8);

		orig -= 8 - orig[-1];

		free(orig);
	}

protected:
	void alloc(int size) {
		_data = aligned_malloc(size);
		_alloc = size;
	}

	void grow(int size) {
		if (_data) {
			aligned_free(_data);
		}

		alloc(size);
	}

	// Versions that call aligned_malloc_zero instead:

	void allocZero(int size) {
		_data = aligned_malloc_zero(size);
		_alloc = size;
	}

	void growZero(int size) {
		if (_data) {
			aligned_free(_data);
		}

		allocZero(size);
	}

public:
	CAT_INLINE SmartArray() {
		_data = 0;
		_size = 0;
	}
	CAT_INLINE virtual ~SmartArray() {
		if (_data) {
			aligned_free(_data);
			_data = 0;
		}
	}

	CAT_INLINE void resize(int size) {
		if (!_data) {
			alloc(size);
		} else if (size > _alloc) {
			grow(size);
		}

		_size = size;
	}

	// Resize and ensure it is zero (can be faster than just resizing)
	CAT_INLINE void resizeZero(int size) {
		if (!_data) {
			allocZero(size);
		} else if (size > _alloc) {
			growZero(size);
		} else {
			void * CAT_RESTRICT data = _data;
			memset(data, 0x00, size * sizeof(T));
		}

		_size = size;
	}

	CAT_INLINE void fill_00() {
		CAT_DEBUG_ENFORCE(_data != 0);

		void * CAT_RESTRICT data = _data;
		memset(data, 0x00, _size * sizeof(T));
	}

	CAT_INLINE void fill_ff() {
		CAT_DEBUG_ENFORCE(_data != 0);

		void * CAT_RESTRICT data = _data;
		memset(data, 0xff, _size * sizeof(T));
	}

	CAT_INLINE int size() {
		return _size;
	}

	CAT_INLINE T *get() {
		CAT_DEBUG_ENFORCE(_data != 0);

		return _data;
	}

	CAT_INLINE T &operator[](int index) {
		CAT_DEBUG_ENFORCE(_data != 0);
		CAT_DEBUG_ENFORCE(index < _size);

		return _data[index];
	}
};


} // namespace cat

#endif // SMART_ARRAY_HPP

