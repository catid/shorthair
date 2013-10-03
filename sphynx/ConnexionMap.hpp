/*
	Copyright (c) 2009-2012 Christopher A. Taylor.  All rights reserved.

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

#ifndef CAT_SPHYNX_CONNEXION_MAP_HPP
#define CAT_SPHYNX_CONNEXION_MAP_HPP

#include <cat/net/Sockets.hpp>
#include <cat/sphynx/Connexion.hpp>
#include <cat/threads/RWLock.hpp>

/*
	Roaming IP

		Roaming IP is implemented by adding two bytes to the front
	of each c2s packet.  The extra field is used to uniquely identify
	the clients rather than using the IP:port.  This is advantageous
	because even if there is a change-over, any late-arriving packets
	from the previous IP:port source tuple would get lost.

		Instead of the "sanctity" of source routing being used to raise
	the bar against forgeries, forgeries become much easier to attempt
	but they are still foiled by the authenticated encryption layer.
	Because I really detest even this slight lowering of the security
	bar, I am making roaming IP compile-time optional so that it can be
	turned off for desktop-dedicated applications.
*/

namespace cat {


namespace sphynx {


// Maps remote address to connected clients
class CAT_EXPORT ConnexionMap
{
public:
	static const u16 INVALID_KEY = ~(u16)0;
	static const int HASH_TABLE_SIZE = 32768; // Power-of-2
	static const int HASH_TABLE_MASK = HASH_TABLE_SIZE - 1;
	static const int MAX_POPULATION = HASH_TABLE_SIZE / 2;
	static const int CONNECTION_FLOOD_THRESHOLD = 10;

private:
	volatile bool _is_shutdown;

#if defined(CAT_SPHYNX_ROAMING_IP)
	static const int MAP_PREALLOC = 64;
	u32 _flood_salt, _first_free;

	Connexion **_conn_table;
	u16 *_free_table;
	u32 _map_alloc;

#else // IP-based version:
	u32 _flood_salt, _ip_salt, _port_salt;

	struct Slot
	{
		Connexion *conn;
		u8 collision;
	};

	Slot _map_table[HASH_TABLE_SIZE];
#endif // CAT_SPHYNX_ROAMING_IP

	RWLock _table_lock;
	u8 _flood_table[HASH_TABLE_SIZE];

	volatile u32 _count;

public:
	ConnexionMap();
	virtual ~ConnexionMap();

	CAT_INLINE bool IsShutdown() { return _is_shutdown; }
	CAT_INLINE u32 GetCount() { return _count; }

	// Initialize the hash salt
	void Initialize(FortunaOutput *csprng);

#if defined(CAT_SPHYNX_ROAMING_IP)
	// Lookup client by id
	// Returns true if flood guard triggered by address
	bool LookupCheckFlood(Connexion * &connexion, const NetAddr &addr, u16 id);
#else
	// Lookup client by address
	// Returns true if flood guard triggered
	bool LookupCheckFlood(Connexion * &connexion, const NetAddr &addr);
#endif // CAT_SPHYNX_ROAMING_IP

	// Lookup client by key
	Connexion *Lookup(u32 key);

	// Returns ERR_NO_PROBLEMO if insertion succeeds, else an error code
	SphynxError Insert(Connexion *conn);

	// Remove Connexion object from the lookup table
	void Remove(Connexion *conn);

	// Invoke ->RequestShutdown() on all Connexion objects
	void ShutdownAll();
};


} // namespace sphynx


} // namespace cat

#endif // CAT_SPHYNX_CONNEXION_MAP_HPP
