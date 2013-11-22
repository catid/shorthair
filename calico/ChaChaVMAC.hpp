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

/*
    The ChaCha cipher is a symmetric stream cipher based on Salsa20.
    http://cr.yp.to/chacha.html

	This implementation is NOT thread-safe.
*/

#ifndef CAT_CHACHA_VMAC_HPP
#define CAT_CHACHA_VMAC_HPP

#include "VHash.hpp"

namespace cat {


class CAT_EXPORT ChaChaVMAC
{
	u32 _e_state[16], _d_state[16];
	VHash _local_mac, _remote_mac;

public:
	~ChaChaVMAC();

	/*
	 * Initialize(key)
	 *
	 * lkey: Local key (192 bytes)
	 * rkey: Remote key (192 bytes)
	 *
	 * No input checking is performed by this function.
	 */
	void Initialize(const u8 lkey[192], const u8 rkey[192]);

	/*
	 * Encrypt(buffer, bytes)
	 *
	 * Encrypts the from buffer into the to buffer, adding a MAC to the end.
	 *
	 * iv: Message initialization vector (IV)
	 * from: Pointer to plaintext buffer
	 * to: Pointer to output encrypted data buffer
	 * bytes: The length of the plaintext message
	 *
	 * The buffer must have room for the additional 8 bytes, and no input
	 * checking is performed by this function.
	 */
	void Encrypt(u64 iv, const void *from, void *to, int bytes);

	/*
	 * valid = Decrypt(buffer, bytes)
	 *
	 * Decrypts the given buffer in-place, plucking the last 8 bytes off the
	 * end that were added during encryption.
	 *
	 * iv: Message initialization vector (IV)
	 * buffer: The message to decrypt in-place
	 * bytes: Number of bytes in the original plaintext message (not including
	 * the IV added by the encryption process, see above)
	 *
	 * Returns true if the MAC was valid, or false if tampering was detected.
	 *
	 * This function performs no input checking.
	 */
	bool Decrypt(u64 iv, void *buffer, int bytes);
};


} // namespace cat

#endif // CAT_CHACHA_VMAC_HPP
