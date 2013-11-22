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

#ifndef CAT_VHASH_HPP
#define CAT_VHASH_HPP

#include "Platform.hpp"

/*
	Mostly copied from the original VHASH implementation
	by Ted Krovetz (tdk@acm.org) and Wei Dai
	Last modified: 17 APR 08, 1700 PDT

	I stripped out everything that I didn't need, including VMAC in order
	to get at the VHASH algorithm directly.  In my own library I am using
	it integrated tightly with the ChaCha cipher, and only with 8 bytes
	of output.  I stripped out a lot of the beautiful optimization work
	done by the original authors to keep my version simple.

	Read more below.
*/

namespace cat {


/*
	VHash

		The VHash algorithm is an exceptionally fast combinatorial hash
	that has properties sufficient for a reasonable guarantee that
	different inputs produce different hashes.  It is not a particularly
	good hash for data integrity checking.  It is also not at all a secure
	hash like SHA-256.  It is especially efficient, however, when used
	for Wegman-Carter message authentication.

		With a good encryption algorithm it can produce a Message
	Authentication Code (MAC).  I intend to use it for implementing
	VMAC-ChaCha, which is realized by adding the VHash output to zero
	bytes after they have been encrypted.

		So it will work like this:

		Step 1: Produce message IV, and use it to set up ChaCha, write it.
		Step 2: Write out 8 bytes of zeroes, and the message to encrypt.
		Step 3: Encrypt the 8 bytes of zeroes + the message with ChaCha.
		Step 4: Compute VHash for the encrypted message bytes.
		Step 5: XOR it into the encrypted zero bytes.

	This is essentially the same as encrypting VHash of the ciphertext
	since ChaCha is a stream cipher that XOR combines with plaintext.

	With this construction, the hash function is keyed, and you can
	think of VHash as a randomly-chosen hash from a family of hashes.
	An attacker would have to guess which hash is being used, and since
	the output is always encrypted, very few hints are dropped about
	the hash function key.

	Normal VMAC-AES will add the output of keyed AES to VHash as I
	understand it.  So I am basically just replacing AES with ChaCha,
	and generating some more keystream from ChaCha to cover the VHash.
*/
class CAT_EXPORT VHash
{
	static const int NHBYTES = 128;
	static const int NH_KEY_WORDS = NHBYTES / 8; // 16

	u64 _nhkey[NH_KEY_WORDS];
	u64 _polykey[2];
	u64 _l3key[2];

public:
	// Securely wipes memory
	~VHash();

	// Initialize using a large 160 byte random key
	void SetKey(const u8 key[160]); // 160 = 128 + 16 + 16

	// Hash data into 8 bytes
	u64 Hash(const void *data, int bytes);
};


} // namespace cat

#endif // CAT_VHASH_HPP
