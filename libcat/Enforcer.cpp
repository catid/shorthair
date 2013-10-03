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

#include "Enforcer.hpp"
using namespace cat;

#if defined(CAT_OS_WINDOWS)
# include <process.h>
#endif

#if defined(CAT_ISA_X86)

#if defined(CAT_WORD_64) && defined(CAT_COMPILER_MSVC)
# define CAT_ARTIFICIAL_BREAKPOINT { ::DebugBreak(); }
#elif defined(CAT_ASM_INTEL)
# define CAT_ARTIFICIAL_BREAKPOINT { CAT_ASM_BEGIN int 3 CAT_ASM_END }
#elif defined(CAT_ASM_ATT)
# define CAT_ARTIFICIAL_BREAKPOINT { CAT_ASM_BEGIN "int $3" CAT_ASM_END }
#else
# error "wut"
#endif

#else
#include <signal.h>
# define CAT_ARTIFICIAL_BREAKPOINT raise(SIGTRAP);
#endif

#include <cstdio>
using namespace std;

void cat::RuntimeAssertionFailure(const char *locus)
{
	fprintf(stderr, "Runtime assertion failure: %s\n", locus);

	CAT_ARTIFICIAL_BREAKPOINT;
}

