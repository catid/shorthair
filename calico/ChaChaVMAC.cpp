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

#include "ChaChaVMAC.hpp"
#include "EndianNeutral.hpp"
#include <string.h>
using namespace cat;

static const int ROUNDS = 8; // Multiple of 2

#define QUARTERROUND(A,B,C,D)							\
	x[A] += x[B]; x[D] = CAT_ROL32(x[D] ^ x[A], 16);	\
	x[C] += x[D]; x[B] = CAT_ROL32(x[B] ^ x[C], 12);	\
	x[A] += x[B]; x[D] = CAT_ROL32(x[D] ^ x[A], 8);		\
	x[C] += x[D]; x[B] = CAT_ROL32(x[B] ^ x[C], 7);

// Mixing function
#define CHACHA_MIX()	\
	for (int round = ROUNDS; round > 0; round -= 2) \
	{								\
		QUARTERROUND(0, 4, 8,  12)	\
		QUARTERROUND(1, 5, 9,  13)	\
		QUARTERROUND(2, 6, 10, 14)	\
		QUARTERROUND(3, 7, 11, 15)	\
		QUARTERROUND(0, 5, 10, 15)	\
		QUARTERROUND(1, 6, 11, 12)	\
		QUARTERROUND(2, 7, 8,  13)	\
		QUARTERROUND(3, 4, 9,  14)	\
	}

// Copy state into registers
#define CHACHA_COPY(state)					\
	state[12] = (u32)block_counter;			\
	state[13] = (u32)(block_counter >> 32);	\
	state[14] = (u32)iv;					\
	state[15] = (u32)(iv >> 32);			\
	for (int ii = 0; ii < 16; ++ii)			\
		x[ii] = state[ii];


//// ChaChaVMAC

ChaChaVMAC::~ChaChaVMAC()
{
	CAT_SECURE_OBJCLR(_e_state);
	CAT_SECURE_OBJCLR(_d_state);
}

static const u32 InitialState[12] = {
	0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
	// These are from BLAKE-32:
	0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
	// Took the rest of these from the SHA-256 SBOX constants:
	0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13
};

void ChaChaVMAC::Initialize(const u8 lkey[192], const u8 rkey[192])
{
	const int KEY_WORDS = 8; // 256-bit key

	// Set encryption key
	const u32 *e32 = reinterpret_cast<const u32*>( lkey );
	memcpy(_e_state, InitialState, sizeof(InitialState));
	for (int ii = 0; ii < KEY_WORDS; ++ii)
		_e_state[ii] ^= getLE(e32[ii]);

	// Set decryption key
	const u32 *d32 = reinterpret_cast<const u32*>( rkey );
	memcpy(_d_state, InitialState, sizeof(InitialState));
	for (int ii = 0; ii < KEY_WORDS; ++ii)
		_d_state[ii] ^= getLE(d32[ii]);

	// Set MAC keys
	_local_mac.SetKey(lkey + 32);
	_remote_mac.SetKey(rkey + 32);
}

void ChaChaVMAC::Encrypt(u64 iv, const void *from, void *to, int bytes)
{
	register u32 x[16];

	u64 block_counter = 0;
	CHACHA_COPY(_e_state);
	CHACHA_MIX();

	// Store the last two keystream words for encrypting the MAC later
	u32 mac_keystream[2] = {
		x[14] + _e_state[14],
		x[15] + _e_state[15]
	};

	// Encrypt the data:

	const u32 *from32 = reinterpret_cast<const u32*>( from );
	u32 *to32 = reinterpret_cast<u32*>( to );
	int left = bytes;

	// If we have enough keystream to cover the whole buffer,
	if (left > 56)
	{
		// Encrypt using the full remainder of keystream
		for (int ii = 0; ii < 14; ++ii)
			to32[ii] = from32[ii] ^ getLE(x[ii] + _e_state[ii]);

		// Increment data pointer
		from32 += 14;
		to32 += 14;
		left -= 56;

		// For each remaining full block,
		do
		{
			++block_counter;
			CHACHA_COPY(_e_state);
			CHACHA_MIX();

			if (left < 64) break;

			for (int ii = 0; ii < 16; ++ii)
				to32[ii] = from32[ii] ^ getLE(x[ii] + _e_state[ii]);

			from32 += 16;
			to32 += 16;
			left -= 64;

		} while (left > 0);
	}

	// For remainder of final block,
	if (left > 0)
	{
		int words = left / 4;

		for (int ii = 0; ii < words; ++ii)
			to32[ii] = from32[ii] ^ getLE(x[ii] + _e_state[ii]);

		// Handle final <4 bytes
		int remainder = left % 4;
		if (remainder > 0)
		{
			const u8 *from8 = reinterpret_cast<const u8*>( from32 + words );
			u8 *to8 = reinterpret_cast<u8*>( to32 + words );
			u32 final_key = getLE(x[words] + _e_state[words]);

			switch (remainder)
			{
			case 3: to8[2] = from8[2] ^ (u8)(final_key >> 16);
			case 2: to8[1] = from8[1] ^ (u8)(final_key >> 8);
			case 1: to8[0] = from8[0] ^ (u8)final_key;
			}
		}
	}

	// Attach MAC:
	{
		// Hash the encrypted buffer
		u64 mac = _local_mac.Hash(to, bytes);

		u8 *to8 = reinterpret_cast<u8*>( to );
		u32 *overhead = reinterpret_cast<u32*>( to8 + bytes );

		// Encrypt and attach the MAC to the end
		overhead[0] = getLE((u32)mac ^ mac_keystream[0]);
		overhead[1] = getLE((u32)(mac >> 32) ^ mac_keystream[1]);
	}

	CAT_SECURE_OBJCLR(x);
}

bool ChaChaVMAC::Decrypt(u64 iv, void *buffer, int bytes)
{
	register u32 x[16];

	u64 block_counter = 0;
	CHACHA_COPY(_d_state);
	CHACHA_MIX();

	// Store the last two keystream words for decrypting the MAC
	u32 mac_keystream[2] = {
		x[14] + _d_state[14],
		x[15] + _d_state[15]
	};

	// Recover and verify MAC:
	{
		// Hash the encrypted buffer
		u64 mac = _remote_mac.Hash(buffer, bytes);

		u8 *text8 = reinterpret_cast<u8*>( buffer );
		const u32 *overhead = reinterpret_cast<const u32*>( text8 + bytes );

		// If generated MAC does not match the provided MAC,
		u32 delta = getLE(overhead[0]) ^ (u32)mac ^ mac_keystream[0];
		delta |= getLE(overhead[1]) ^ (u32)(mac >> 32) ^ mac_keystream[1];

		if (delta != 0)
		{
			CAT_SECURE_OBJCLR(x);

			return false;
		}
	}

	// Decrypt the data:

	u32 *text = reinterpret_cast<u32*>( buffer );
	int left = bytes;

	// If we have enough keystream to cover the whole buffer,
	if (left > 56)
	{
		// Decrypt using the full remainder of keystream
		for (int ii = 0; ii < 14; ++ii)
			text[ii] ^= getLE(x[ii] + _d_state[ii]);

		// Increment data pointer
		text += 14;
		left -= 56;

		// For each remaining full block,
		do
		{
			++block_counter;
			CHACHA_COPY(_d_state);
			CHACHA_MIX();

			if (left < 64) break;

			for (int ii = 0; ii < 16; ++ii)
				text[ii] ^= getLE(x[ii] + _d_state[ii]);

			text += 16;
			left -= 64;

		} while (left > 0);
	}

	// For remainder of final block,
	if (left > 0)
	{
		int words = left / 4;

		for (int ii = 0; ii < words; ++ii)
			text[ii] ^= getLE(x[ii] + _d_state[ii]);

		// Handle final <4 bytes
		int remainder = left % 4;
		if (remainder > 0)
		{
			u8 *text8 = reinterpret_cast<u8*>( text + words );
			u32 final_key = getLE(x[words] + _d_state[words]);

			switch (remainder)
			{
			case 3: text8[2] ^= (u8)(final_key >> 16);
			case 2: text8[1] ^= (u8)(final_key >> 8);
			case 1: text8[0] ^= (u8)final_key;
			}
		}
	}

	CAT_SECURE_OBJCLR(x);

	return true;
}
