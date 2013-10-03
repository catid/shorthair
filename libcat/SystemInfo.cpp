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

#include <cat/port/SystemInfo.hpp>
#include <cstdlib>
#include <cstdio>
using namespace std;
using namespace cat;

#if defined(CAT_OS_WINDOWS)
# include <cat/math/BitMath.hpp>
# include <WinIoCtl.h>
	typedef BOOL (WINAPI* PGetLogicalProcessorInformation)(PSYSTEM_LOGICAL_PROCESSOR_INFORMATION, PDWORD);
#elif defined(CAT_OS_LINUX) || defined(CAT_OS_AIX) || defined(CAT_OS_SOLARIS) || defined(CAT_OS_IRIX)
# include <unistd.h>
#elif defined(CAT_OS_OSX) || defined(CAT_OS_BSD)
# include <sys/sysctl.h>
# include <unistd.h>
#elif defined(CAT_OS_HPUX)
# include <sys/mpctl.h>
#endif

// Add your compiler here if it supports aligned malloc
#if defined(CAT_COMPILER_MSVC)
# define CAT_HAS_ALIGNED_ALLOC
# define aligned_malloc _aligned_malloc
# define aligned_realloc _aligned_realloc
# define aligned_free _aligned_free
#endif

static u32 GetCacheLineBytes()
{
	// Based on work by Nick Strupat (http://strupat.ca/)

	u32 discovered_cache_line_size = 0;

#if defined(CAT_OS_OSX) || defined(CAT_OS_BSD)

	u64 line_size;
	size_t size = sizeof(line_size);

	if (0 == sysctlbyname("hw.cachelinesize", &line_size, &size, 0, 0))
	{
		discovered_cache_line_size = (u32)line_size;
	}

#elif defined(CAT_OS_WINDOWS)

	DWORD buffer_size = 0;
	SYSTEM_LOGICAL_PROCESSOR_INFORMATION *buffer = 0;
	PGetLogicalProcessorInformation pGetLogicalProcessorInformation;

	pGetLogicalProcessorInformation = (PGetLogicalProcessorInformation)GetProcAddress(GetModuleHandleA("kernel32.dll"), "pGetLogicalProcessorInformation");

	if (pGetLogicalProcessorInformation)
	{
		pGetLogicalProcessorInformation(0, &buffer_size);

		if (buffer_size > 0)
		{
			buffer = (SYSTEM_LOGICAL_PROCESSOR_INFORMATION *)malloc(buffer_size);
			pGetLogicalProcessorInformation(&buffer[0], &buffer_size);

			for (int i = 0; i < (int)(buffer_size / sizeof(SYSTEM_LOGICAL_PROCESSOR_INFORMATION)); ++i)
			{
				if (buffer[i].Relationship == RelationCache &&
					buffer[i].Cache.Level == 1)
				{
					discovered_cache_line_size = (u32)buffer[i].Cache.LineSize;
					break;
				}
			}

			free(buffer);
		}
	}

#elif defined(CAT_OS_LINUX)

	FILE *file = fopen("/sys/devices/system/cpu/cpu0/cache/index0/coherency_line_size", "r");

	if (file)
	{
		if (1 != fscanf(file, "%d", &discovered_cache_line_size))
		{
			discovered_cache_line_size = 0;
		}

		fclose(file);
	}

#elif defined(CAT_OS_XBOX) || defined(CAT_OS_PS3)

	discovered_cache_line_size = 128;

#endif

	// Validate cache line size and use default if discovery has failed
	if (discovered_cache_line_size <= 0 ||
		discovered_cache_line_size > 1024 ||
		!CAT_IS_POWER_OF_2(discovered_cache_line_size))
	{
		discovered_cache_line_size = CAT_DEFAULT_CACHE_LINE_SIZE; // From Config.hpp
	}

	return discovered_cache_line_size;
}

static u32 GetProcessorCount()
{
	u32 processor_count = 0;

#if defined(CAT_OS_WINDOWS)

	ULONG_PTR ulpProcessAffinityMask, ulpSystemAffinityMask;
	GetProcessAffinityMask(GetCurrentProcess(), &ulpProcessAffinityMask, &ulpSystemAffinityMask);
	processor_count = (u32)BitCount(ulpProcessAffinityMask);

#elif defined(CAT_OS_LINUX) || defined(CAT_OS_AIX) || defined(CAT_OS_SOLARIS)

	processor_count = (u32)sysconf(_SC_NPROCESSORS_ONLN);

#elif defined(CAT_OS_OSX) || defined(CAT_OS_BSD)

	int mib[4];
	mib[0] = CTL_HW;
	mib[1] = HW_AVAILCPU;

	size_t len = sizeof(processor_count);
	sysctl(mib, 2, &processor_count, &len, 0, 0);

	if (processor_count < 1)
	{
		mib[1] = HW_NCPU;

		len = sizeof(processor_count);
		sysctl(mib, 2, &processor_count, &len, 0, 0);
	}

#elif defined(CAT_OS_HPUX)

	processor_count = (u32)mpctl(MPC_GETNUMSPUS, 0, 0);

#elif defined(CAT_OS_IRIX)

	processor_count = (u32)sysconf(_SC_NPROC_ONLN);

#endif

	return processor_count > 1 ? processor_count : 1;
}

static u32 GetPageSize()
{
	u32 page_size = 0;

#if defined(CAT_OS_WINDOWS)

	SYSTEM_INFO sys_info;
	GetSystemInfo(&sys_info);
	page_size = sys_info.dwPageSize;

#elif defined(CAT_OS_OSX) || defined(CAT_OS_BSD)

	page_size = (u32)getpagesize();

#else

	page_size = (u32)sysconf(_SC_PAGE_SIZE);

#endif

	return page_size > 0 ? page_size : CAT_DEFAULT_PAGE_SIZE;
}

static u32 GetAllocationGranularity()
{
	u32 alloc_gran = 0;

#if defined(CAT_OS_WINDOWS)

	SYSTEM_INFO sys_info;
	GetSystemInfo(&sys_info);
	alloc_gran = sys_info.dwAllocationGranularity;

#else

	return GetPageSize();

#endif

	return alloc_gran > 0 ? alloc_gran : CAT_DEFAULT_ALLOCATION_GRANULARITY;
}

static u32 GetMaxSectorSize()
{
	u32 sector_size = 0;

#if defined(CAT_OS_WINDOWS)

	/*
		Sector size is 512 almost everywhere, so this isn't a huge deal
		but I wanted this to be more future-proof and faster on new disks.

		In Windows, the normal way to get sector size is to call GetDiskFreeSpace(),
		but this function takes over twice as long as doing it with DeviceIoControl().
		Also, with Vista+, this is the only way to get *physical* sector sizes since
		there is an emulation layer for new disks that will fake 512B sector sizes.
	*/

	// If OS version is Vista+,
	OSVERSIONINFOA info;
	info.dwOSVersionInfoSize = sizeof(info);
	GetVersionExA(&info);
	bool use_physical_sector_size = info.dwMajorVersion >= 6;

	// Set up device names
	const int MAX_DRIVES = 16;
	char device_name[20] = "\\\\.\\PhysicalDrive";

	// For each drive to test,
	for (int ii = 0; ii < MAX_DRIVES; ++ii)
	{
		// Generate device name string
		if (ii < 10)
		{
			device_name[17] = ii + '0';
			device_name[18] = '\0';
		}
		else
		{
			device_name[17] = '1';
			device_name[18] = ii - 10 + '0';
			device_name[19] = '\0';
		}

		// Open device
		HANDLE device = CreateFileA(device_name, 0, FILE_SHARE_READ | FILE_SHARE_WRITE, 0, OPEN_EXISTING, 0, 0);
		if (device != INVALID_HANDLE_VALUE)
		{
			u32 bytes_per_sector = 0;

			u8 buffer[4096];
			CAT_OBJCLR(buffer);
			DWORD bytes;

			// If Vista+,
			if (use_physical_sector_size)
			{
				STORAGE_PROPERTY_QUERY query;
				CAT_OBJCLR(query);
				query.PropertyId = StorageAccessAlignmentProperty;
				query.QueryType = PropertyStandardQuery;

				// Read alignment property
				if (DeviceIoControl(device, IOCTL_STORAGE_QUERY_PROPERTY, &query, sizeof(query), buffer, sizeof(buffer), &bytes, 0))
				{
					STORAGE_ACCESS_ALIGNMENT_DESCRIPTOR *descriptor = (STORAGE_ACCESS_ALIGNMENT_DESCRIPTOR*)buffer;

					if (bytes >= sizeof(STORAGE_ACCESS_ALIGNMENT_DESCRIPTOR))
						bytes_per_sector = descriptor->BytesPerPhysicalSector;
				}
			}
			else
			{
				// Read geometry
				if (DeviceIoControl(device, IOCTL_DISK_GET_DRIVE_GEOMETRY_EX, 0, 0, buffer, sizeof(buffer), &bytes, 0))
				{
					DISK_GEOMETRY_EX *geometry = (DISK_GEOMETRY_EX*)buffer;

					if (bytes >= offsetof(DISK_GEOMETRY_EX, Data))
						bytes_per_sector = geometry->Geometry.BytesPerSector;
				}
			}

			// Validate input is a power of two and highest so far
			if (sector_size < bytes_per_sector &&
				CAT_IS_POWER_OF_2(bytes_per_sector))
			{
				sector_size = bytes_per_sector;
			}

			CloseHandle(device);
		}
	}

#else

	return CAT_DEFAULT_SECTOR_SIZE;

#endif

	return sector_size > 0 ? sector_size : CAT_DEFAULT_SECTOR_SIZE;
}


//// SystemInfo

CAT_SINGLETON(SystemInfo);

bool SystemInfo::OnInitialize()
{
	_CacheLineBytes = ::GetCacheLineBytes();
	_ProcessorCount = ::GetProcessorCount();
	_PageSize = ::GetPageSize();
	_AllocationGranularity = ::GetAllocationGranularity();
	_MaxSectorSize = ::GetMaxSectorSize();

	return true;
}
