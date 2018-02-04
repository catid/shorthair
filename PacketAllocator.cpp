/** \file
    \brief Custom Memory Allocator for Packet Data
    \copyright Copyright (c) 2017 Christopher A. Taylor.  All rights reserved.

    Redistribution and use in source and binary forms, with or without
    modification, are permitted provided that the following conditions are met:

    * Redistributions of source code must retain the above copyright notice,
      this list of conditions and the following disclaimer.
    * Redistributions in binary form must reproduce the above copyright notice,
      this list of conditions and the following disclaimer in the documentation
      and/or other materials provided with the distribution.
    * Neither the name of PacketAllocator nor the names of its contributors may be
      used to endorse or promote products derived from this software without
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

#include "PacketAllocator.h"

#include <cstring> // memcpy
#include <cstdlib> // calloc

#if defined(PKTALLOC_ENABLE_ALLOCATOR_INTEGRITY_CHECKS) && defined(PKTALLOC_DEBUG)
    #define ALLOC_DEBUG_INTEGRITY_CHECK() IntegrityCheck();
#else // PKTALLOC_ENABLE_ALLOCATOR_INTEGRITY_CHECKS
    #define ALLOC_DEBUG_INTEGRITY_CHECK() do {} while (false);
#endif // PKTALLOC_ENABLE_ALLOCATOR_INTEGRITY_CHECKS

namespace pktalloc {


//------------------------------------------------------------------------------
// SIMD-Safe Aligned Memory Allocations

static inline uint8_t* SIMDSafeAllocate(size_t size)
{
    uint8_t* data = (uint8_t*)calloc(1, kAlignmentBytes + size);
    if (!data)
        return nullptr;
    unsigned offset = (unsigned)((uintptr_t)data % kAlignmentBytes);
    data += kAlignmentBytes - offset;
    data[-1] = (uint8_t)offset;
    return data;
}

static inline void SIMDSafeFree(void* ptr)
{
    if (!ptr)
        return;
    uint8_t* data = (uint8_t*)ptr;
    unsigned offset = data[-1];
    if (offset >= kAlignmentBytes)
    {
        PKTALLOC_DEBUG_BREAK(); // Should never happen
        return;
    }
    data -= kAlignmentBytes - offset;
    free(data);
}


//------------------------------------------------------------------------------
// Allocator

Allocator::Allocator()
{
    static_assert(kAlignmentBytes == kUnitSize, "update SIMDSafeAllocate");

    HugeChunkStart = SIMDSafeAllocate(kWindowSizeBytes * kPreallocatedWindows);
    if (HugeChunkStart)
    {
        uint8_t* windowStart = HugeChunkStart;

        PreferredWindowsHead = nullptr;
        PreferredWindowsTail = (WindowHeader*)windowStart;
        PreferredWindowsCount = kPreallocatedWindows;

        // For each window to preallocate:
        for (unsigned i = 0; i < kPreallocatedWindows; ++i)
        {
            WindowHeader* windowHeader = (WindowHeader*)windowStart;
            windowStart += kWindowSizeBytes;

            windowHeader->Used.ClearAll();
            windowHeader->FreeUnitCount    = kWindowMaxUnits;
            windowHeader->ResumeScanOffset = 0;
            windowHeader->Prev             = nullptr;
            windowHeader->Next             = PreferredWindowsHead;
            windowHeader->InFullList       = false;
            windowHeader->Preallocated     = true;
 
            PreferredWindowsHead = windowHeader;
        }
    }

    ALLOC_DEBUG_INTEGRITY_CHECK();
}

Allocator::~Allocator()
{
    for (WindowHeader* node = PreferredWindowsHead, *next; node; node = next)
    {
        next = node->Next;
        if (!node->Preallocated)
            SIMDSafeFree(node);
    }
    for (WindowHeader* node = FullWindowsHead, *next; node; node = next)
    {
        next = node->Next;
        if (!node->Preallocated)
            SIMDSafeFree(node);
    }
    SIMDSafeFree(HugeChunkStart);
}

unsigned Allocator::GetMemoryUsedBytes() const
{
    unsigned sum = 0;
    for (WindowHeader* node = PreferredWindowsHead; node; node = node->Next)
        sum += kWindowMaxUnits - node->FreeUnitCount;
    for (WindowHeader* node = FullWindowsHead; node; node = node->Next)
        sum += kWindowMaxUnits - node->FreeUnitCount;
    return sum * kUnitSize;
}

unsigned Allocator::GetMemoryAllocatedBytes() const
{
    return (unsigned)((PreferredWindowsCount + FullWindowsCount) * kWindowMaxUnits * kUnitSize);
}

bool Allocator::IntegrityCheck() const
{
#ifdef PKTALLOC_SHRINK
    PKTALLOC_DEBUG_ASSERT(PreferredWindowsCount >= EmptyWindowCount);
#endif // PKTALLOC_SHRINK

    unsigned emptyCount = 0;
    unsigned preallocatedCount = 0;

    PKTALLOC_DEBUG_ASSERT(!PreferredWindowsHead || PreferredWindowsHead->Prev == nullptr);
    PKTALLOC_DEBUG_ASSERT(!PreferredWindowsTail || PreferredWindowsTail->Next == nullptr);

    unsigned ii = 0;
    for (WindowHeader* windowHeader = PreferredWindowsHead; windowHeader; windowHeader = windowHeader->Next, ++ii)
    {
        if (ii >= PreferredWindowsCount)
        {
            PKTALLOC_DEBUG_BREAK(); // Should never happen
            return false;
        }
        unsigned jj = 0;
        for (WindowHeader* other = PreferredWindowsHead; other; other = other->Next, ++jj)
        {
            if (windowHeader == other && ii != jj)
            {
                PKTALLOC_DEBUG_BREAK(); // Should never happen
                return false;
            }
        }
        if (windowHeader->InFullList)
        {
            PKTALLOC_DEBUG_BREAK(); // Should never happen
            return false;
        }
        if (windowHeader->FreeUnitCount <= 0 || windowHeader->FreeUnitCount > kWindowMaxUnits)
        {
            PKTALLOC_DEBUG_BREAK(); // Should never happen
            return false;
        }
        if (windowHeader->ResumeScanOffset > kWindowMaxUnits)
        {
            PKTALLOC_DEBUG_BREAK(); // Should never happen
            return false;
        }
        unsigned setCount = windowHeader->Used.RangePopcount(0, kWindowMaxUnits);
        if (setCount != kWindowMaxUnits - windowHeader->FreeUnitCount)
        {
            PKTALLOC_DEBUG_BREAK(); // Should never happen
            return false;
        }
        if (windowHeader->Preallocated)
            ++preallocatedCount;
        else if (windowHeader->FreeUnitCount == kWindowMaxUnits)
            ++emptyCount;
    }
    PKTALLOC_DEBUG_ASSERT(ii == PreferredWindowsCount);

    ii = 0;
    for (WindowHeader* windowHeader = FullWindowsHead, *prev = nullptr; windowHeader; windowHeader = windowHeader->Next, ++ii)
    {
        PKTALLOC_DEBUG_ASSERT(windowHeader->Prev == prev);
        prev = windowHeader;

        if (ii >= FullWindowsCount)
        {
            PKTALLOC_DEBUG_BREAK(); // Should never happen
            return false;
        }
        for (WindowHeader* other = PreferredWindowsHead; other; other = other->Next)
        {
            if (windowHeader == other)
            {
                PKTALLOC_DEBUG_BREAK(); // Should never happen
                return false;
            }
        }
        unsigned jj = 0;
        for (WindowHeader* other = FullWindowsHead; other; other = other->Next, ++jj)
        {
            if (windowHeader == other && ii != jj)
            {
                PKTALLOC_DEBUG_BREAK(); // Should never happen
                return false;
            }
        }
        if (!windowHeader->InFullList)
        {
            PKTALLOC_DEBUG_BREAK(); // Should never happen
            return false;
        }
        if (windowHeader->FreeUnitCount > kPreferredThresholdUnits)
        {
            PKTALLOC_DEBUG_BREAK(); // Should never happen
            return false;
        }
        if (windowHeader->ResumeScanOffset > kWindowMaxUnits)
        {
            PKTALLOC_DEBUG_BREAK(); // Should never happen
            return false;
        }
        unsigned setCount = windowHeader->Used.RangePopcount(0, kWindowMaxUnits);
        if (setCount != kWindowMaxUnits - windowHeader->FreeUnitCount)
        {
            PKTALLOC_DEBUG_BREAK(); // Should never happen
            return false;
        }
        if (windowHeader->Preallocated)
            ++preallocatedCount;
    }
    PKTALLOC_DEBUG_ASSERT(ii == FullWindowsCount);

    if (preallocatedCount != kPreallocatedWindows)
    {
        PKTALLOC_DEBUG_BREAK(); // Should never happen
        return false;
    }
#ifdef PKTALLOC_SHRINK
    if (emptyCount != EmptyWindowCount)
    {
        PKTALLOC_DEBUG_BREAK(); // Should never happen
        return false;
    }
#endif // PKTALLOC_SHRINK
    return true;
}

uint8_t* Allocator::Allocate(unsigned bytes)
{
    if (bytes <= 0)
        return nullptr;

    ALLOC_DEBUG_INTEGRITY_CHECK();

    // Calculate number of units required by this allocation
    // Note: +1 for the AllocationHeader
    const unsigned units = (bytes + kUnitSize - 1) / kUnitSize + 1;

    if (units > kFallbackThresholdUnits)
        return fallbackAllocate(bytes);

    for (WindowHeader* windowHeader = PreferredWindowsHead, *prev = nullptr; windowHeader; prev = windowHeader, windowHeader = windowHeader->Next)
    {
        PKTALLOC_DEBUG_ASSERT(!windowHeader->InFullList);

        if (windowHeader->FreeUnitCount < units)
            continue;

        // Walk the holes in the bitmask:
        UsedMaskT& usedMask  = windowHeader->Used;
        unsigned regionStart = windowHeader->ResumeScanOffset;
        while (regionStart < usedMask.kValidBits)
        {
            regionStart = usedMask.FindFirstClear(regionStart);
            unsigned regionEnd = regionStart + units;

            // If we ran out of space:
            if (regionEnd > usedMask.kValidBits)
                break;

            regionEnd = usedMask.FindFirstSet(regionStart + 1, regionEnd);
            PKTALLOC_DEBUG_ASSERT(regionEnd > regionStart);
            PKTALLOC_DEBUG_ASSERT(regionEnd <= usedMask.kValidBits);

            if (regionEnd - regionStart < units)
            {
                regionStart = regionEnd + 1;
                continue;
            }
            regionEnd = regionStart + units;

            // Carve out region
            uint8_t* region = (uint8_t*)windowHeader + kWindowHeaderBytes + regionStart * kUnitSize;
            AllocationHeader* regionHeader = (AllocationHeader*)region;
#ifdef PKTALLOC_DEBUG
            regionHeader->Canary = AllocationHeader::kCanaryExpected;
#endif // PKTALLOC_DEBUG
            regionHeader->Header    = windowHeader;
            regionHeader->UsedUnits = units;
            regionHeader->Freed     = false;

            // Update window header
#ifdef PKTALLOC_SHRINK
            if (windowHeader->FreeUnitCount >= kWindowMaxUnits && !windowHeader->Preallocated)
            {
                PKTALLOC_DEBUG_ASSERT(EmptyWindowCount > 0);
                --EmptyWindowCount;
            }
#endif // PKTALLOC_SHRINK
            windowHeader->FreeUnitCount -= units;
            usedMask.SetRange(regionStart, regionStart + units);
            windowHeader->ResumeScanOffset = regionStart + units;

            // Move this window to the full list if we cannot make another allocation of the same size
            const unsigned kMinRemaining = units;
            WindowHeader* moveStopWindow = (windowHeader->ResumeScanOffset + kMinRemaining > kWindowMaxUnits) ? windowHeader->Next : windowHeader;
            moveFirstFewWindowsToFull(moveStopWindow);

            uint8_t* data = region + kUnitSize;
#ifdef PKTALLOC_SCRUB_MEMORY
            memset(data, 0, (units - 1) * kUnitSize);
#endif // PKTALLOC_SCRUB_MEMORY
            PKTALLOC_DEBUG_ASSERT((uintptr_t)data % kUnitSize == 0);
            PKTALLOC_DEBUG_ASSERT((uint8_t*)regionHeader >= (uint8_t*)regionHeader->Header + kWindowHeaderBytes);
            PKTALLOC_DEBUG_ASSERT(regionHeader->GetUnitStart() < kWindowMaxUnits);
            PKTALLOC_DEBUG_ASSERT(regionHeader->GetUnitStart() + regionHeader->UsedUnits <= kWindowMaxUnits);
            return data;
        }
    }

    // Move all preferred windows to full since none of them worked out
    moveFirstFewWindowsToFull(nullptr);

    return allocateFromNewWindow(units);
}

void Allocator::moveFirstFewWindowsToFull(WindowHeader* stopWindow)
{
    unsigned movedCount = 0;
    WindowHeader* moveHead = FullWindowsHead;
    WindowHeader* keepHead = nullptr;
    WindowHeader* keepTail = nullptr;

    for (WindowHeader* windowHeader = PreferredWindowsHead, *next; windowHeader != stopWindow; windowHeader = next)
    {
        next = windowHeader->Next;

        // If this window should stay in the preferred list:
        if (windowHeader->FreeUnitCount >= kPreferredThresholdUnits)
        {
            // Reset the free block scan from the top for this window since we missed some holes
            // But we will move it to the end of the preferred list since it seems spotty
            windowHeader->ResumeScanOffset = 0;

            // Place it in the "keep" list for now
            if (keepTail)
                keepTail->Next = windowHeader;
            else
                keepHead = windowHeader;
            keepTail = windowHeader;
        }
        else
        {
            // Move the window to the full list
            windowHeader->InFullList = true;
            ++movedCount;
            windowHeader->Next = moveHead;
            if (moveHead)
                moveHead->Prev = windowHeader;
            windowHeader->Prev = nullptr;
            moveHead = windowHeader;
        }
    }

    // Update FullWindows list
    FullWindowsHead = moveHead;
    FullWindowsCount += movedCount;

    // Update PreferredWindows list
    PreferredWindowsCount -= movedCount;
    if (stopWindow)
    {
#ifdef PKTALLOC_DEBUG
        stopWindow->Prev = nullptr;
#endif // PKTALLOC_DEBUG
        PreferredWindowsHead = stopWindow;
        PKTALLOC_DEBUG_ASSERT(PreferredWindowsTail != nullptr);

        if (keepHead)
        {
            PreferredWindowsTail->Next = keepHead;
            PreferredWindowsTail = keepTail;
            keepTail->Next = nullptr;
        }
    }
    else
    {
        PreferredWindowsHead = keepHead;
        PreferredWindowsTail = keepTail;
        if (keepHead)
            keepTail->Next = nullptr;
    }

    ALLOC_DEBUG_INTEGRITY_CHECK();
}

uint8_t* Allocator::allocateFromNewWindow(unsigned units)
{
    ALLOC_DEBUG_INTEGRITY_CHECK();

    uint8_t* headerStart = SIMDSafeAllocate(kWindowSizeBytes);
    if (!headerStart)
        return nullptr; // Allocation failure

    // Update window header
    WindowHeader* windowHeader = (WindowHeader*)headerStart;
    windowHeader->Used.ClearAll();
    windowHeader->Used.SetRange(0, units);
    windowHeader->FreeUnitCount = kWindowMaxUnits - units;
    windowHeader->ResumeScanOffset = units;
    windowHeader->InFullList = false;
    windowHeader->Next = PreferredWindowsHead;
    windowHeader->Preallocated = false;

    // Insert into PreferredWindows list
    if (PreferredWindowsHead)
        PreferredWindowsHead->Prev = windowHeader;
    else
        PreferredWindowsTail = windowHeader;
    PreferredWindowsHead = windowHeader;
    ++PreferredWindowsCount;

    // Carve out region
    AllocationHeader* regionHeader = (AllocationHeader*)(headerStart + kWindowHeaderBytes);
#ifdef PKTALLOC_DEBUG
    regionHeader->Canary = AllocationHeader::kCanaryExpected;
#endif // PKTALLOC_DEBUG
    regionHeader->Header    = windowHeader;
    regionHeader->UsedUnits = units;
    regionHeader->Freed     = false;

    uint8_t* data = (uint8_t*)regionHeader + kUnitSize;
#ifdef PKTALLOC_SCRUB_MEMORY
    memset(data, 0, (units - 1) * kUnitSize);
#endif // PKTALLOC_SCRUB_MEMORY
    PKTALLOC_DEBUG_ASSERT((uintptr_t)data % kUnitSize == 0);

    ALLOC_DEBUG_INTEGRITY_CHECK();

    return data;
}

uint8_t* Allocator::Reallocate(uint8_t* ptr, unsigned bytes, Realloc behavior)
{
    ALLOC_DEBUG_INTEGRITY_CHECK();

    if (!ptr)
        return Allocate(bytes);
    if (bytes <= 0)
    {
        Free(ptr);
        return nullptr;
    }
    PKTALLOC_DEBUG_ASSERT((uintptr_t)ptr % kUnitSize == 0);

    AllocationHeader* regionHeader = (AllocationHeader*)(ptr - kUnitSize);
#ifdef PKTALLOC_DEBUG
    if (regionHeader->Canary != AllocationHeader::kCanaryExpected)
    {
        PKTALLOC_DEBUG_BREAK(); // Buffer overflow detected
        return nullptr;
    }
#endif // PKTALLOC_DEBUG
    if (regionHeader->Freed)
    {
        PKTALLOC_DEBUG_BREAK(); // Double-free
        return Allocate(bytes);
    }

    const unsigned existingUnits = regionHeader->UsedUnits;
#ifndef PKTALLOC_DISABLE_ALLOCATOR
    PKTALLOC_DEBUG_ASSERT(!regionHeader->Header || existingUnits <= kFallbackThresholdUnits);
#endif // PKTALLOC_DISABLE_ALLOCATOR

    // If the existing allocation is big enough:
    const unsigned requestedUnits = (bytes + kUnitSize - 1) / kUnitSize + 1;
    if (requestedUnits <= existingUnits)
        return ptr; // No change needed

    // Allocate new data
    uint8_t* newPtr = Allocate(bytes);
    if (!newPtr)
        return nullptr;

    // Copy old data
    if (behavior == Realloc::CopyExisting)
        memcpy(newPtr, ptr, (existingUnits - 1) * kUnitSize);

    Free(ptr);

    ALLOC_DEBUG_INTEGRITY_CHECK();

    return newPtr;
}

void Allocator::Shrink(uint8_t* ptr, unsigned bytes)
{
    ALLOC_DEBUG_INTEGRITY_CHECK();

    if (!ptr)
        return;
    PKTALLOC_DEBUG_ASSERT((uintptr_t)ptr % kUnitSize == 0);

    AllocationHeader* regionHeader = (AllocationHeader*)(ptr - kUnitSize);
#ifdef PKTALLOC_DEBUG
    if (regionHeader->Canary != AllocationHeader::kCanaryExpected)
    {
        PKTALLOC_DEBUG_BREAK(); // Buffer overflow detected
        return;
    }
#endif // PKTALLOC_DEBUG
    if (regionHeader->Freed)
    {
        PKTALLOC_DEBUG_BREAK(); // Double-free
        return;
    }

    // Calculate number of units required by this allocation
    // Note: +1 for the AllocationHeader
    const unsigned unitsNeeded = (bytes + kUnitSize - 1) / kUnitSize + 1;
    const unsigned unitsCurrent = regionHeader->UsedUnits;

    // If the allocation can shrink:
    if (unitsNeeded < unitsCurrent)
    {
        WindowHeader* windowHeader = regionHeader->Header;
        if (!windowHeader)
        {
            // Fallback allocation: We cannot resize this region
            return;
        }

        PKTALLOC_DEBUG_ASSERT((uint8_t*)regionHeader >= (uint8_t*)regionHeader->Header + kWindowHeaderBytes);
        const unsigned regionStart = regionHeader->GetUnitStart();
        PKTALLOC_DEBUG_ASSERT(regionStart < kWindowMaxUnits);
        PKTALLOC_DEBUG_ASSERT(regionStart + regionHeader->UsedUnits <= kWindowMaxUnits);

        const unsigned regionEndNew = regionStart + unitsNeeded;
        PKTALLOC_DEBUG_ASSERT(regionEndNew <= kWindowMaxUnits);
        PKTALLOC_DEBUG_ASSERT((regionStart + unitsCurrent) > regionEndNew);

        // Resume scanning from this hole next time
        if (windowHeader->ResumeScanOffset > regionEndNew)
            windowHeader->ResumeScanOffset = regionEndNew;

        // Clear the units we gave up
        windowHeader->Used.ClearRange(regionEndNew, regionStart + unitsCurrent);

        // Give back the unit count
        windowHeader->FreeUnitCount += unitsCurrent - unitsNeeded;

        // Update unit count
        regionHeader->UsedUnits = unitsNeeded;

        // Note that this will not move a full window to the empty list,
        // but when this allocation is freed it may be added later.
    }

    ALLOC_DEBUG_INTEGRITY_CHECK();
}

void Allocator::Free(uint8_t* ptr)
{
    ALLOC_DEBUG_INTEGRITY_CHECK();

    if (!ptr)
        return;
    PKTALLOC_DEBUG_ASSERT((uintptr_t)ptr % kUnitSize == 0);

    AllocationHeader* regionHeader = (AllocationHeader*)(ptr - kUnitSize);
#ifdef PKTALLOC_DEBUG
    if (regionHeader->Canary != AllocationHeader::kCanaryExpected)
    {
        PKTALLOC_DEBUG_BREAK(); // Buffer overflow detected
        return;
    }
#endif // PKTALLOC_DEBUG
    if (regionHeader->Freed)
    {
        PKTALLOC_DEBUG_BREAK(); // Double-free
        return;
    }
    regionHeader->Freed = true;

    WindowHeader* windowHeader = regionHeader->Header;
    if (!windowHeader)
    {
        fallbackFree(ptr);
        return;
    }

    const unsigned units = regionHeader->UsedUnits;
    PKTALLOC_DEBUG_ASSERT(units >= 2 && units <= kFallbackThresholdUnits);

    PKTALLOC_DEBUG_ASSERT((uint8_t*)regionHeader >= (uint8_t*)regionHeader->Header + kWindowHeaderBytes);
    unsigned regionStart = regionHeader->GetUnitStart();
    PKTALLOC_DEBUG_ASSERT(regionStart < kWindowMaxUnits);
    PKTALLOC_DEBUG_ASSERT(regionStart + regionHeader->UsedUnits <= kWindowMaxUnits);

    unsigned regionEnd = regionStart + units;

    // Resume scanning from this hole next time
    if (windowHeader->ResumeScanOffset > regionStart)
        windowHeader->ResumeScanOffset = regionStart;

    // Clear the units it was using
    windowHeader->Used.ClearRange(regionStart, regionEnd);

    // Give back the unit count
    windowHeader->FreeUnitCount += units;

    // If we may want to promote this to Preferred:
    if (windowHeader->FreeUnitCount >= kPreferredThresholdUnits &&
        windowHeader->InFullList)
    {
        windowHeader->InFullList = false;

        // Restart scanning from the front
        windowHeader->ResumeScanOffset = 0;

        // Remove from the FullWindows list
        WindowHeader* prev = windowHeader->Prev;
        WindowHeader* next = windowHeader->Next;
        if (prev)
            prev->Next = next;
        else
            FullWindowsHead = next;
        if (next)
            next->Prev = prev;
        PKTALLOC_DEBUG_ASSERT(FullWindowsCount > 0);
        --FullWindowsCount;

        // Insert at end of the PreferredWindows list
        ++PreferredWindowsCount;
        windowHeader->Prev = nullptr;
        windowHeader->Next = nullptr;
        if (PreferredWindowsTail)
            PreferredWindowsTail->Next = windowHeader;
        else
            PreferredWindowsHead = windowHeader;
        PreferredWindowsTail = windowHeader;
    }

#ifdef PKTALLOC_SHRINK
    if (windowHeader->FreeUnitCount >= kWindowMaxUnits && !windowHeader->Preallocated)
    {
        // If we should do some bulk cleanup:
        if (++EmptyWindowCount >= kEmptyWindowCleanupThreshold)
            freeEmptyWindows();
    }
#endif // PKTALLOC_SHRINK

    ALLOC_DEBUG_INTEGRITY_CHECK();
}

#ifdef PKTALLOC_SHRINK

void Allocator::freeEmptyWindows()
{
    if (EmptyWindowCount <= kEmptyWindowMinimum)
        return;

    ALLOC_DEBUG_INTEGRITY_CHECK();

    for (WindowHeader* windowHeader = PreferredWindowsHead, *next, *prev = nullptr; windowHeader; windowHeader = next)
    {
        next = windowHeader->Next;

        // If this window can be reclaimed:
        if (windowHeader->FreeUnitCount >= kWindowMaxUnits && !windowHeader->Preallocated)
        {
            if (prev)
                prev->Next = next;
            else
                PreferredWindowsHead = next;
            if (!next)
                PreferredWindowsTail = prev;

            SIMDSafeFree(windowHeader);

            PKTALLOC_DEBUG_ASSERT(PreferredWindowsCount > 0);
            --PreferredWindowsCount;

            PKTALLOC_DEBUG_ASSERT(EmptyWindowCount > 0);
            if (--EmptyWindowCount <= kEmptyWindowMinimum)
                break;
        }
        else
        {
            prev = windowHeader;
        }
    }

    ALLOC_DEBUG_INTEGRITY_CHECK();
}

#endif // PKTALLOC_SHRINK

uint8_t* Allocator::fallbackAllocate(unsigned bytes)
{
    // Calculate number of units required by this allocation
    // Note: +1 for the AllocationHeader
    const unsigned units = (bytes + kUnitSize - 1) / kUnitSize + 1;

    uint8_t* ptr = SIMDSafeAllocate(kUnitSize * units);
    if (!ptr)
        return nullptr;

    AllocationHeader* regionHeader = (AllocationHeader*)ptr;
#ifdef PKTALLOC_DEBUG
    regionHeader->Canary    = AllocationHeader::kCanaryExpected;
#endif // PKTALLOC_DEBUG
    regionHeader->Freed     = false;
    regionHeader->Header    = nullptr;
    regionHeader->UsedUnits = units;

    return ptr + kUnitSize;
}

void Allocator::fallbackFree(uint8_t* ptr)
{
    PKTALLOC_DEBUG_ASSERT(ptr);
    SIMDSafeFree(ptr - kUnitSize);
}


} // namespace pktalloc
