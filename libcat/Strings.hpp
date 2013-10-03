/*
	Copyright (c) 2009-2010 Christopher A. Taylor.  All rights reserved.

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

#ifndef CAT_STRINGS_HPP
#define CAT_STRINGS_HPP

/*
	These are ANSI C String function that do not work with UNICODE, UTF-8, etc.
*/

#include <cat/Platform.hpp>

#if defined(CAT_COMPILER_MSVC)
#include <string.h> // _stricmp
#elif defined(CAT_COMPILER_GCC)
#include <strings.h> // strcasecmp
#endif

namespace cat {

// Portable, safe, faster itoa: Converts x to string, returning number of characters produced
// Returns false if output is clipped (13 character buffer is good enough for 32-bit decimal)
bool CAT_EXPORT IntegerToArray(s32 x, char *outs, int outs_buf_size, int radix = 10);

// Returns true if character is alphabetic
CAT_INLINE bool IsAlpha(char ch)
{
	return (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z');
}

// Returns true if character is alphabetic or numeric
CAT_INLINE bool IsAlphanumeric(char ch)
{
	return IsAlpha(ch) || (ch >= '0' && ch <= '9');
}


// iStrEqual(): Returns true if strings match.  Case-insensitive

#if defined(CAT_COMPILER_MSVC)

	CAT_INLINE bool iStrEqual(const char *A, const char *B)
	{
		return _stricmp(A, B) == 0;
	}

#elif defined(CAT_COMPILER_GCC)

	CAT_INLINE bool iStrEqual(const char *A, const char *B)
	{
		return strcasecmp(A, B) == 0;
	}

#else

# define CAT_UNKNOWN_BUILTIN_ISTRCMP
	bool iStrEqual(const char *A, const char *B);

#endif


// Get length of string that has a maximum length (potentially no trailing nul)
u32 CAT_EXPORT GetFixedStrLen(const char *str, u32 max_len);


// Set a fixed string buffer (zero-padded) from a variable-length string,
// both either zero or length-terminated.  Returns length of copied string
u32 CAT_EXPORT SetFixedStr(char *dest, u32 dest_len, const char *src, u32 src_max_len);


// Returns true if buffer contains any non-zero bytes
bool CAT_EXPORT IsZeroFixedBuffer(const void *buffer, u32 bytes);


// Replaces all similar-looking glyphs with a common character
char CAT_EXPORT DesimilarizeCharacter(char ch);

// Replaces all similar-looking glyphs with common characters while copying a string
void CAT_EXPORT CopyDesimilarizeString(const char *from, char *to);

// Replaces all similar-looking glyphs with common characters in a fixed string
u32 CAT_EXPORT DesimilarizeFixedString(char *str, u32 max_len);

// Copies the input string to an output string replacing lowercase letters with their uppercase equivalents
void CAT_EXPORT CopyToUppercaseString(const char *from, char *to);

// Copies the input string to an output string replacing uppercase letters with their lowercase equivalents
void CAT_EXPORT CopyToLowercaseString(const char *from, char *to);

// Copies the contents of a line from a text file into a nul-terminated output buffer
int CAT_EXPORT ReadLineFromTextFileBuffer(u8 *data, u32 remaining, char *outs, int len);


//// Nul-Terminated Fixed-Length String

template<int MAX_LEN>
class NulTermFixedStr
{
	char _str[MAX_LEN+1];

public:
	CAT_INLINE void Clear()
	{
		_str[0] = '\0';
	}

	CAT_INLINE void SetFromRangeString(const char *str, int len)
	{
		if (len > MAX_LEN)
			len = MAX_LEN;

		memcpy(_str, str, len);
		_str[len] = '\0';
	}

	CAT_INLINE void SetFromNulTerminatedString(const char *str)
	{
		CAT_STRNCPY(_str, str, sizeof(_str));
	}

	CAT_INLINE void SetFromInteger(int x, int radix = 10)
	{
		IntegerToArray(x, _str, sizeof(_str), radix);
	}

	CAT_INLINE operator char*()
	{
		return _str;
	}

	// Case-insensitive check if first 'len' characters of two strings match
	bool CaseCompare(const char *str, int len)
	{
		char a, b, *fixed = _str;

		// NOTE: str may not be nul-terminated

		// For each character,
		while (len--)
		{
			a = *fixed;
			b = *str;

			// If a character differs,
			if (a != b)
			{
				// If a is upper case,
				if (a >= 'A' && a <= 'Z')
				{
					// If switching it to lower case doesn't fix it,
					if (a + 'a' - 'A' != b)
						return false;
				}
				else // a is lower case
				{
					// If switching it to upper case doesn't fix it,
					if (a + 'A' - 'a' != b)
						return false;
				}
			}

			// Next character for each string
			++fixed;
			++str;
		}

		return true;
	}
};


} // namespace cat

#endif // CAT_STRINGS_HPP
