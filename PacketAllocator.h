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

#pragma once

/** \page PktAlloc Packet Optimized Memory Allocator Module

    It turned out that malloc() and calloc() amount to a great deal of
    the overhead of managing queued packet data.

    Tuned for packet queues:
    The allocator is tuned for allocations around 1000 bytes that are freed in
    roughly the same order that they are allocated.

    Advantages:
    + Eliminates codec performance bottleneck.
    + All allocation requests will be aligned for SIMD operations.
    + No thread safety or debug check overhead penalties.
    + No contention with allocations from users of the library.
    + Aligned realloc() is supported.
    + Simpler cleanup: All memory automatically freed in destructor.
    + Self-contained library that is easy to reuse.

    Disadvantages:
    + Uses more memory than strictly necessary.
    + Requires some tuning for new applications.
*/

#include <stdint.h>

#ifdef _WIN32
    #include <intrin.h> // __popcnt64
#endif


namespace pktalloc {



//------------------------------------------------------------------------------
// Configuration

/**
    This configuration is currently optimized for the Siamese library, but it
    can be tuned for a specific application by editing this section.
*/

/// Disable the allocator
//#define PKTALLOC_DISABLE

/// Define this to shrink the allocated memory when it is no longer used
//#define PKTALLOC_SHRINK

/// Zero out allocated memory
//#define PKTALLOC_SCRUB_MEMORY

/// Enable costly integrity checks before and after each operation
//#define PKTALLOC_ENABLE_ALLOCATOR_INTEGRITY_CHECKS


#if defined(__AVX2__) || (defined (_MSC_VER) && _MSC_VER >= 1900)
    #define PKTALLOC_ALIGN_BYTES 32 /**< Allocating on 256-bit boundaries */
#else // __AVX2__
    #define PKTALLOC_ALIGN_BYTES 16 /**< Allocating on 128-bit boundaries */
#endif // __AVX2__

/// Alignment requirements of library
static const unsigned kAlignmentBytes = PKTALLOC_ALIGN_BYTES;

/// Minimum allocation unit. Must be a power of two
static const unsigned kUnitSize = kAlignmentBytes;

/// Maximum number of units per window, tuned for ~1400 byte packets.
/// Tune this if the data sizes are larger
static const unsigned kWindowMaxUnits = 2048;

/// Preallocated windows (about 128 KB on desktop)
static const unsigned kPreallocatedWindows = 2;

/// PKTALLOC_SHRINK: Keep some windows around
static const unsigned kEmptyWindowMinimum = 32;

/// PKTALLOC_SHRINK: Lazy cleanup after a certain point
static const unsigned kEmptyWindowCleanupThreshold = 64;


//------------------------------------------------------------------------------
// Platform

/// Compiler-specific debug break
#if defined(_DEBUG) || defined(DEBUG)
    #define PKTALLOC_DEBUG
    #ifdef _WIN32
        #define PKTALLOC_DEBUG_BREAK() __debugbreak()
    #else
        #define PKTALLOC_DEBUG_BREAK() __builtin_trap()
    #endif
    #define PKTALLOC_DEBUG_ASSERT(cond) { if (!(cond)) { PKTALLOC_DEBUG_BREAK(); } }
#else
    #define PKTALLOC_DEBUG_BREAK() do {} while (false);
    #define PKTALLOC_DEBUG_ASSERT(cond) do {} while (false);
#endif

/// Compiler-specific force inline keyword
#ifdef _MSC_VER
    #define PKTALLOC_FORCE_INLINE inline __forceinline
#else
    #define PKTALLOC_FORCE_INLINE inline __attribute__((always_inline))
#endif

PKTALLOC_FORCE_INLINE unsigned NextAlignedOffset(unsigned offset)
{
    return (offset + kAlignmentBytes - 1) & ~(kAlignmentBytes - 1);
}


//------------------------------------------------------------------------------
// Portable Intrinsics

/// Returns number of bits set in the 64-bit value
PKTALLOC_FORCE_INLINE unsigned PopCount64(uint64_t x)
{
#ifdef _MSC_VER
#ifdef _WIN64
    return (unsigned)__popcnt64(x);
#else
    return (unsigned)(__popcnt((uint32_t)x) + __popcnt((uint32_t)(x >> 32)));
#endif
#else // GCC
    return (unsigned)__builtin_popcountll(x);
#endif
}

/// Returns lowest bit index 0..63 where the first non-zero bit is found
/// Precondition: x != 0
PKTALLOC_FORCE_INLINE unsigned TrailingZeros64(uint64_t x)
{
#ifdef _MSC_VER
#ifdef _WIN64
    unsigned long index;
    // Note: Ignoring result because x != 0
    _BitScanForward64(&index, x);
    return (unsigned)index;
#else
    unsigned long index;
    if (0 != _BitScanForward(&index, (uint32_t)x))
        return (unsigned)index;
    // Note: Ignoring result because x != 0
    _BitScanForward(&index, (uint32_t)(x >> 32));
    return (unsigned)index + 32;
#endif
#else
    // Note: Ignoring return value of 0 because x != 0
    return (unsigned)__builtin_ffsll(x) - 1;
#endif
}


//------------------------------------------------------------------------------
// CustomBitSet

/// Custom std::bitset implementation for speed
template<unsigned N>
struct CustomBitSet
{
    static const unsigned kValidBits = N;
    typedef uint64_t WordT;
    static const unsigned kWordBits = sizeof(WordT) * 8;
    static const unsigned kWords = (kValidBits + kWordBits - 1) / kWordBits;
    static const WordT kAllOnes = UINT64_C(0xffffffffffffffff);

    WordT Words[kWords];


    CustomBitSet()
    {
        ClearAll();
    }

    void ClearAll()
    {
        for (unsigned i = 0; i < kWords; ++i)
            Words[i] = 0;
    }
    void SetAll()
    {
        for (unsigned i = 0; i < kWords; ++i)
            Words[i] = kAllOnes;
    }
    void Set(unsigned bit)
    {
        const unsigned word = bit / kWordBits;
        const WordT mask = (WordT)1 << (bit % kWordBits);
        Words[word] |= mask;
    }
    void Clear(unsigned bit)
    {
        const unsigned word = bit / kWordBits;
        const WordT mask = (WordT)1 << (bit % kWordBits);
        Words[word] &= ~mask;
    }
    bool Check(unsigned bit) const
    {
        const unsigned word = bit / kWordBits;
        const WordT mask = (WordT)1 << (bit % kWordBits);
        return 0 != (Words[word] & mask);
    }

    /**
        Returns the popcount of the bits within the given range.

        bitStart < kValidBits: First bit to test
        bitEnd <= kValidBits: Bit to stop at (non-inclusive)
    */
    unsigned RangePopcount(unsigned bitStart, unsigned bitEnd)
    {
        static_assert(kWordBits == 64, "Update this");

        if (bitStart >= bitEnd)
            return 0;

        unsigned wordIndex = bitStart / kWordBits;
        const unsigned wordEnd = bitEnd / kWordBits;

        // Eliminate low bits of first word
        WordT word = Words[wordIndex] >> (bitStart % kWordBits);

        // Eliminate high bits of last word if there is just one word
        if (wordEnd == wordIndex)
            return PopCount64(word << (kWordBits - (bitEnd - bitStart)));

        // Count remainder of first word
        unsigned count = PopCount64(word);

        // Accumulate popcount of full words
        while (++wordIndex < wordEnd)
            count += PopCount64(Words[wordIndex]);

        // Eliminate high bits of last word if there is one
        unsigned lastWordBits = bitEnd - wordIndex * kWordBits;
        if (lastWordBits > 0)
            count += PopCount64(Words[wordIndex] << (kWordBits - lastWordBits));

        return count;
    }

    /**
        Returns the bit index where the first cleared bit is found.
        Returns kValidBits if all bits are set.

        bitStart < kValidBits: Index to start looking
    */
    unsigned FindFirstClear(unsigned bitStart)
    {
        static_assert(kWordBits == 64, "Update this");

        unsigned wordStart = bitStart / kWordBits;

        WordT word = ~Words[wordStart] >> (bitStart % kWordBits);
        if (word != 0)
        {
            unsigned offset = 0;
            if ((word & 1) == 0)
                offset = TrailingZeros64(word);
            return bitStart + offset;
        }

        for (unsigned i = wordStart + 1; i < kWords; ++i)
        {
            word = ~Words[i];
            if (word != 0)
                return i * kWordBits + TrailingZeros64(word);
        }

        return kValidBits;
    }

    /**
        Returns the bit index where the first set bit is found.
        Returns 'bitEnd' if all bits are clear.

        bitStart < kValidBits: Index to start looking
        bitEnd <= kValidBits: Index to stop looking at
    */
    unsigned FindFirstSet(unsigned bitStart, unsigned bitEnd = kValidBits)
    {
        static_assert(kWordBits == 64, "Update this");

        unsigned wordStart = bitStart / kWordBits;

        WordT word = Words[wordStart] >> (bitStart % kWordBits);
        if (word != 0)
        {
            unsigned offset = 0;
            if ((word & 1) == 0)
                offset = TrailingZeros64(word);
            return bitStart + offset;
        }

        const unsigned wordEnd = (bitEnd + kWordBits - 1) / kWordBits;

        for (unsigned i = wordStart + 1; i < wordEnd; ++i)
        {
            word = Words[i];
            if (word != 0)
                return i * kWordBits + TrailingZeros64(word);
        }

        return bitEnd;
    }

    /**
        Set a range of bits

        bitStart < kValidBits: Index at which to start setting
        bitEnd <= kValidBits: Bit to stop at (non-inclusive)
    */
    void SetRange(unsigned bitStart, unsigned bitEnd)
    {
        if (bitStart >= bitEnd)
            return;

        unsigned wordStart = bitStart / kWordBits;
        const unsigned wordEnd = bitEnd / kWordBits;

        bitStart %= kWordBits;

        if (wordEnd == wordStart)
        {
            // This implies x=(bitStart % kWordBits) and y=(bitEnd % kWordBits)
            // are in the same word.  Also: x < y, y < 64, y - x < 64.
            bitEnd %= kWordBits;
            WordT mask = ((WordT)1 << (bitEnd - bitStart)) - 1; // 1..63 bits
            mask <<= bitStart;
            Words[wordStart] |= mask;
            return;
        }

        // Set the end of the first word
        Words[wordStart] |= kAllOnes << bitStart;

        // Whole words at a time
        for (unsigned i = wordStart + 1; i < wordEnd; ++i)
            Words[i] = kAllOnes;

        // Set first few bits of the last word
        unsigned lastWordBits = bitEnd - wordEnd * kWordBits;
        if (lastWordBits > 0)
        {
            WordT mask = ((WordT)1 << lastWordBits) - 1; // 1..63 bits
            Words[wordEnd] |= mask;
        }
    }

    /**
        Clear a range of bits

        bitStart < kValidBits: Index at which to start clearing
        bitEnd <= kValidBits: Bit to stop at (non-inclusive)
    */
    void ClearRange(unsigned bitStart, unsigned bitEnd)
    {
        if (bitStart >= bitEnd)
            return;

        unsigned wordStart = bitStart / kWordBits;
        const unsigned wordEnd = bitEnd / kWordBits;

        bitStart %= kWordBits;

        if (wordEnd == wordStart)
        {
            // This implies x=(bitStart % kWordBits) and y=(bitEnd % kWordBits)
            // are in the same word.  Also: x < y, y < 64, y - x < 64.
            bitEnd %= kWordBits;
            WordT mask = ((WordT)1 << (bitEnd - bitStart)) - 1; // 1..63 bits
            mask <<= bitStart;
            Words[wordStart] &= ~mask;
            return;
        }

        // Clear the end of the first word
        Words[wordStart] &= ~(kAllOnes << bitStart);

        // Whole words at a time
        for (unsigned i = wordStart + 1; i < wordEnd; ++i)
            Words[i] = 0;

        // Clear first few bits of the last word
        unsigned lastWordBits = bitEnd - wordEnd * kWordBits;
        if (lastWordBits > 0)
        {
            WordT mask = ((WordT)1 << lastWordBits) - 1; // 1..63 bits
            Words[wordEnd] &= ~mask;
        }
    }
};


//------------------------------------------------------------------------------
// Enumerations

/// Maintain data in buffer during reallocation?
enum class Realloc
{
    Uninitialized,  // Resize the buffer and discard contents
    CopyExisting    // Copy existing data in the buffer
};


//------------------------------------------------------------------------------
// Allocator

/// Instance of a packet allocator with its own block of memory
class Allocator
{
public:
    Allocator();
    ~Allocator();

    /// Allocation API
    uint8_t* Allocate(unsigned bytes);
    uint8_t* Reallocate(uint8_t* ptr, unsigned bytes, Realloc behavior);
    void Shrink(uint8_t* ptr, unsigned bytes);
    void Free(uint8_t* ptr);

    /// Placement new/delete
    template<class T>
    inline T* Construct()
    {
        uint8_t* mem = Allocate((unsigned)sizeof(T));
        if (!mem)
            return nullptr;
        return new (mem)T();
    }
    template<class T>
    inline void Destruct(T* obj)
    {
        if (obj)
        {
            obj->~T();
            Free((uint8_t*)obj);
        }
    }

    /// Statistics API
    unsigned GetMemoryUsedBytes() const;
    unsigned GetMemoryAllocatedBytes() const;
    bool IntegrityCheck() const;

protected:
    typedef CustomBitSet<kWindowMaxUnits> UsedMaskT;

    /// When we can only fit a few in a window, switch to fallback
#ifdef PKTALLOC_DISABLE_ALLOCATOR
    static const unsigned kFallbackThresholdUnits = 0;
#else
    static const unsigned kFallbackThresholdUnits = kWindowMaxUnits / 4;
#endif

    /// This is at the front of each allocation window
    struct WindowHeader
    {
        UsedMaskT Used;

        /// Total number of free units
        unsigned FreeUnitCount;

        /// Offset to resume scanning for a free spot
        unsigned ResumeScanOffset;

        /// Next, prev window header in the set
        WindowHeader* Next;
        WindowHeader* Prev;

        /// Set to true if this is part of the full list
        bool InFullList;

        /// Set to true if this is part of the preallocated chunk
        bool Preallocated;
    };

    /// This is tagged on the front of each allocation so that Realloc()
    /// and Free() are faster.
    struct AllocationHeader
    {
#ifdef PKTALLOC_DEBUG
        static const uint32_t kCanaryExpected = 0xaabbccdd;
        uint32_t Canary;
#endif // PKTALLOC_DEBUG

        /// Is this allocation already freed? (some minimal self-diagnostics)
        uint32_t Freed;

        /// Number of units used right now
        uint32_t UsedUnits;

        /// Header for this window
        /// Note: This will be set to nullptr for fallback allocations
        WindowHeader* Header;

        /// Calculate which unit this allocation starts at in the window
        unsigned GetUnitStart()
        {
            return (unsigned)((uint8_t*)this - ((uint8_t*)Header + kWindowHeaderBytes)) / kUnitSize;
        }
    };

    static_assert(kUnitSize >= (unsigned)sizeof(AllocationHeader), "too small");

    /// Round the window header size up to alignment size
    static const unsigned kWindowHeaderBytes = (unsigned)(sizeof(WindowHeader) + kAlignmentBytes - 1) & ~(kAlignmentBytes - 1);

    /// Number of bytes per window
    static const unsigned kWindowSizeBytes = kWindowHeaderBytes + kWindowMaxUnits * kUnitSize;


    /// Preallocated windows on startup
    uint8_t* HugeChunkStart = nullptr;

    /// List of "preferred" windows with lower utilization
    /// We switch Preferred to Full when a scan fails to find an empty slot
    WindowHeader* PreferredWindowsHead = nullptr;
    WindowHeader* PreferredWindowsTail = nullptr;
    unsigned PreferredWindowsCount = 0;

    /// List of "full" windows with higher utilization
    WindowHeader* FullWindowsHead = nullptr;
    unsigned FullWindowsCount = 0;

    /// We switch Full to Preferred when it drops below 1/4 utilization
    static const unsigned kPreferredThresholdUnits = 3 * kWindowMaxUnits / 4;


#ifdef PKTALLOC_SHRINK
    /// Counter of the number of empty windows, which triggers us to clean house on Free()
    unsigned EmptyWindowCount = 0;

    /// Walk the preferred list and free any empty windows
    void freeEmptyWindows();
#endif

    /// Move windows to full list between [PreferredWindowHead, stopWindow) not including stopWindow
    /// If stopWindow is nullptr, then it will attempt to move all windows
    void moveFirstFewWindowsToFull(WindowHeader* stopWindow);

    /// Allocate the units from a new window
    uint8_t* allocateFromNewWindow(unsigned units);

    /// Fallback functions used when the custom allocator will not work
    uint8_t* fallbackAllocate(unsigned bytes);
    void fallbackFree(uint8_t* ptr);
};


} // namespace pktalloc
