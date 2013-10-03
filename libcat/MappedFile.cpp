/*
	Copyright (c) 2013 Game Closure.  All rights reserved.

	Redistribution and use in source and binary forms, with or without
	modification, are permitted provided that the following conditions are met:

	* Redistributions of source code must retain the above copyright notice,
	  this list of conditions and the following disclaimer.
	* Redistributions in binary form must reproduce the above copyright notice,
	  this list of conditions and the following disclaimer in the documentation
	  and/or other materials provided with the distribution.
	* Neither the name of GCIF nor the names of its contributors may be used
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

#include "MappedFile.hpp"
using namespace cat;

#ifdef CAT_COMPILE_MMAP

#if defined(CAT_OS_LINUX) || defined(CAT_OS_OSX)
# include <sys/mman.h>
# include <sys/stat.h>
# include <fcntl.h>
# include <errno.h>
#endif

#if defined(CAT_OS_WINDOWS)
# include "WindowsInclude.hpp"
#elif defined(CAT_OS_LINUX) || defined(CAT_OS_AIX) || defined(CAT_OS_SOLARIS) || defined(CAT_OS_IRIX)
# include <unistd.h>
#elif defined(CAT_OS_OSX) || defined(CAT_OS_BSD)
# include <sys/sysctl.h>
# include <unistd.h>
#elif defined(CAT_OS_HPUX)
# include <sys/mpctl.h>
#endif

static u32 GetAllocationGranularity()
{
	u32 alloc_gran = 0;

#if defined(CAT_OS_WINDOWS)

	SYSTEM_INFO sys_info;
	GetSystemInfo(&sys_info);
	alloc_gran = sys_info.dwAllocationGranularity;

#elif defined(CAT_OS_OSX) || defined(CAT_OS_BSD)

	alloc_gran = (u32)getpagesize();

#else

	alloc_gran = (u32)sysconf(_SC_PAGE_SIZE);

#endif

	return alloc_gran > 0 ? alloc_gran : CAT_DEFAULT_ALLOCATION_GRANULARITY;
}


//// MappedFile

MappedFile::MappedFile()
{
	_len = 0;

#if defined(CAT_OS_WINDOWS)

	_file = INVALID_HANDLE_VALUE;

#else

	_file = -1;

#endif
}

MappedFile::~MappedFile()
{
	Close();
}

bool MappedFile::OpenRead(const char *path, bool read_ahead, bool no_cache)
{
	Close();

	_readonly = true;

#if defined(CAT_OS_WINDOWS)

	u32 access_pattern = !read_ahead ? FILE_FLAG_RANDOM_ACCESS : FILE_FLAG_SEQUENTIAL_SCAN;

	_file = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING, access_pattern, 0);
	if (_file == INVALID_HANDLE_VALUE)
	{
		return false;
	}

	if (!GetFileSizeEx(_file, (LARGE_INTEGER*)&_len))
	{
		return false;
	}

#else

	_file = open(path, O_RDONLY, (mode_t)0444);

	if (_file == -1) {
		return false;
	} else {
		_len = lseek(_file, 0, SEEK_END);

		if (_len <= 0) {
			return false;
		} else {
#ifdef F_RDAHEAD
			if (read_ahead) {
				fcntl(_file, F_RDAHEAD, 1);
			}
#endif

#ifdef F_NOCACHE
			if (no_cache) {
				fcntl(_file, F_NOCACHE, 1);
			}
#endif
		}
	}

#endif

	return true;
}

bool MappedFile::OpenWrite(const char *path, u64 size)
{
	Close();

	_readonly = false;
	_len = size;

#if defined(CAT_OS_WINDOWS)

	const u32 access_pattern = FILE_FLAG_SEQUENTIAL_SCAN;

	_file = CreateFileA(path, GENERIC_WRITE|GENERIC_READ, FILE_SHARE_WRITE, 0, CREATE_ALWAYS, access_pattern, 0);
	if (_file == INVALID_HANDLE_VALUE)
	{
		return false;
	}

	// Set file size
	if (!SetFilePointerEx(_file, *(LARGE_INTEGER*)&_len, 0, FILE_BEGIN)) {
		return false;
	}
	if (!SetEndOfFile(_file)) {
		return false;
	}

#else

	_file = open(path, O_RDWR|O_CREAT|O_TRUNC, (mode_t)0666);

	if (_file == -1) {
		return false;
	} else {
		if (-1 == lseek(_file, size - 1, SEEK_SET)) {
			return false;
		} else {
			if (1 != write(_file, "", 1)) {
				return false;
			}
		}
	}

#endif

	return true;
}

void MappedFile::Close()
{
#if defined(CAT_OS_WINDOWS)

	if (_file != INVALID_HANDLE_VALUE)
	{
		CloseHandle(_file);
		_file = INVALID_HANDLE_VALUE;
	}

#else

	if (_file != -1) {
		close(_file);
		_file = -1;
	}

#endif

	_len = 0;
}


//// MappedView

MappedView::MappedView()
{
	_data = 0;
	_length = 0;
	_offset = 0;

#if defined(CAT_OS_WINDOWS)

	_map = 0;

#else

	_map = MAP_FAILED;

#endif
}

MappedView::~MappedView()
{
	Close();
}

bool MappedView::Open(MappedFile *file)
{
	Close();

	if (!file || !file->IsValid()) return false;

	_file = file;

#if defined(CAT_OS_WINDOWS)

	const u32 flags = file->IsReadOnly() ? PAGE_READONLY : PAGE_READWRITE;
	_map = CreateFileMapping(file->_file, 0, flags, 0, 0, 0);
	if (!_map)
	{
		return false;
	}

#endif

	return true;
}

u8 *MappedView::MapView(u64 offset, u32 length)
{
	if (length == 0) {
		length = static_cast<u32>( _file->GetLength() );
	}

	if (offset) {
		u32 granularity = GetAllocationGranularity();

		// Bring offset back to the previous allocation granularity
		u32 mask = granularity - 1;
		u32 masked = (u32)offset & mask;
		if (masked)
		{
			offset -= masked;
			length += masked;
		}
	}

#if defined(CAT_OS_WINDOWS)

	u32 flags = FILE_MAP_READ;
	if (!_file->IsReadOnly()) {
		flags |= FILE_MAP_WRITE;
	}

	_data = (u8*)MapViewOfFile(_map, flags, (u32)(offset >> 32), (u32)offset, length);
	if (!_data)
	{
		return 0;
	}

#else

	int prot = PROT_READ;
	if (!_file->_readonly) {
		prot |= PROT_WRITE;
	}

	_map = mmap(0, length, prot, MAP_SHARED, _file->_file, offset);

	if (_map == MAP_FAILED) {
		return 0;
	}

	_data = reinterpret_cast<u8*>( _map );

#endif

	_offset = offset;
	_length = length;

	return _data;
}

void MappedView::Close()
{
#if defined(CAT_OS_WINDOWS)

	if (_data)
	{
		UnmapViewOfFile(_data);
		_data = 0;
	}
	if (_map)
	{
		CloseHandle(_map);
		_map = 0;
	}

#else

	if (_map != MAP_FAILED)
	{
		munmap(_map, _length);
		_map = MAP_FAILED;
	}
	_data = 0;

#endif

	_length = 0;
	_offset = 0;
}

#endif // CAT_COMPILE_MMAP

