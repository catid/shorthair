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

#ifndef CAT_SYSTEM_INFO_HPP
#define CAT_SYSTEM_INFO_HPP

#include <cat/lang/Singleton.hpp>

namespace cat {


class CAT_EXPORT SystemInfo : public Singleton<SystemInfo>
{
	bool OnInitialize();

	// Number of bytes in each CPU cache line
	u32 _CacheLineBytes;

	// Number of processors
	u32 _ProcessorCount;

	// Page size
	u32 _PageSize;

	// Allocation granularity
	u32 _AllocationGranularity;

	// Maximum sector size of all fixed disks
	u32 _MaxSectorSize;

public:
	CAT_INLINE u32 GetCacheLineBytes() { return _CacheLineBytes; }
	CAT_INLINE u32 GetProcessorCount() { return _ProcessorCount; }
	CAT_INLINE u32 GetPageSize() { return _PageSize; }
	CAT_INLINE u32 GetAllocationGranularity() { return _AllocationGranularity; }
	CAT_INLINE u32 GetMaxSectorSize() { return _MaxSectorSize; }
};


} // namespace cat

#endif // CAT_SYSTEM_INFO_HPP
