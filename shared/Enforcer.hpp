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

#ifndef ENFORCER_HPP
#define ENFORCER_HPP

#include "Platform.hpp"

namespace cat {


/*
 * STL-free portable assertion library for debug mode of decoder
 */
void RuntimeAssertionFailure(const char *locus);

#if defined(CAT_USE_ENFORCE_EXPRESSION_STRING)
# define CAT_ENFORCE_EXPRESSION_STRING(exp) "Failed assertion (" #exp ")"
#else
# define CAT_ENFORCE_EXPRESSION_STRING(exp) "Failed assertion"
#endif

#if defined(CAT_USE_ENFORCE_FILE_LINE_STRING)
# define CAT_ENFORCE_FILE_LINE_STRING " at " CAT_FILE_LINE_STRING
#else
# define CAT_ENFORCE_FILE_LINE_STRING ""
#endif

#define CAT_ENFORCE(exp) if ( (exp) == 0 ) { RuntimeAssertionFailure(CAT_ENFORCE_EXPRESSION_STRING(exp) CAT_ENFORCE_FILE_LINE_STRING); }
#define CAT_EXCEPTION() RuntimeAssertionFailure("Exception" CAT_ENFORCE_FILE_LINE_STRING);

#if defined(CAT_DEBUG)
# define CAT_DEBUG_ENFORCE(exp) CAT_ENFORCE(exp)
# define CAT_DEBUG_EXCEPTION() CAT_EXCEPTION()
#else
# define CAT_DEBUG_ENFORCE(exp)
# define CAT_DEBUG_EXCEPTION()
#endif


} // namespace cat

#endif // ENFORCER_HPP

