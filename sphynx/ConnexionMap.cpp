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

#include <cat/sphynx/ConnexionMap.hpp>
#include <cat/hash/Murmur.hpp>
#include <cat/io/Log.hpp>
using namespace cat;
using namespace sphynx;


//// Address hashing helper functions

static CAT_INLINE u32 flood_hash_addr(const NetAddr &addr, u32 salt)
{
	u32 key;

	// If address is IPv6,
	if (addr.Is6())
	{
		// Hash first 64 bits of 128-bit address to 32 bits
		// Right now the last 64 is easy to change if you actually have an IPv6 address
		key = MurmurHash(addr.GetIP6(), (addr.CanDemoteTo4() ? NetAddr::IP6_BYTES : NetAddr::IP6_BYTES/2), salt).Get32();
	}
	else // assuming IPv4 and address is not invalid
	{
		key = addr.GetIP4();

		// Thomas Wang's integer hash function
		// http://www.cris.com/~Ttwang/tech/inthash.htm
		key = (key ^ 61) ^ (key >> 16);
		key = key + (key << 3);
		key = key ^ (key >> 4) ^ salt;
		key = key * 0x27d4eb2d;
		key = key ^ (key >> 15);
	}

	return key;
}

#if !defined(CAT_SPHYNX_ROAMING_IP)

static CAT_INLINE u32 map_hash_addr(const NetAddr &addr, u32 ip_salt, u32 port_salt)
{
	u32 key;

	// If address is IPv6,
	if (addr.Is6())
	{
		// Hash full address because this function is not for flood detection
		key = MurmurHash(addr.GetIP6(), NetAddr::IP6_BYTES, ip_salt).Get32();
	}
	else // assuming IPv4 and address is not invalid
	{
		key = addr.GetIP4();

		// Thomas Wang's integer hash function
		// http://www.cris.com/~Ttwang/tech/inthash.htm
		key = (key ^ 61) ^ (key >> 16);
		key = key + (key << 3);
		key = key ^ (key >> 4) ^ ip_salt;
		key = key * 0x27d4eb2d;
		key = key ^ (key >> 15);
	}

	// Map 16-bit port 1:1 to a random-looking number
	key += (u32)addr.GetPort() * (port_salt*4 + 1);

	return key;
}

#endif // !CAT_SPHYNX_ROAMING_IP


//// ConnexionMap

ConnexionMap::ConnexionMap()
{
#if defined(CAT_SPHYNX_ROAMING_IP)
	_conn_table = 0;
	_free_table = 0;
	_first_free = ConnexionMap::INVALID_KEY;
	_map_alloc = 0;
#else
	CAT_OBJCLR(_map_table);
#endif
	CAT_OBJCLR(_flood_table);
	_is_shutdown = false;
	_count = 0;
}

ConnexionMap::~ConnexionMap()
{
#if defined(CAT_SPHYNX_ROAMING_IP)
	if (_conn_table)
	{
		delete []_conn_table;
		_conn_table = 0;
	}

	if (_free_table)
	{
		delete []_free_table;
		_free_table = 0;
	}
#endif
}

void ConnexionMap::Initialize(FortunaOutput *csprng)
{
#if !defined(CAT_SPHYNX_ROAMING_IP)
	_ip_salt = csprng->Generate();
	_port_salt = csprng->Generate();
#endif
	_flood_salt = csprng->Generate();
}

#if defined(CAT_SPHYNX_ROAMING_IP)

bool ConnexionMap::LookupCheckFlood(Connexion * &connexion, const NetAddr &addr, u16 id)
{
	connexion = Lookup(id);

	// If id is not found,
	if (!connexion)
	{
		// Do flood key computation only if address is not in the address map table
		u32 flood_key = flood_hash_addr(addr, _flood_salt) & HASH_TABLE_MASK;

		// If flood threshold breached,
		return (_flood_table[flood_key] >= CONNECTION_FLOOD_THRESHOLD);
	}

	return false;
}

#else

bool ConnexionMap::LookupCheckFlood(Connexion * &connexion, const NetAddr &addr)
{
	// Hash IP:port:salt to get the hash table key
	u32 key = map_hash_addr(addr, _ip_salt, _port_salt) & HASH_TABLE_MASK;

	AutoReadLock lock(_table_lock);

	if (IsShutdown())
	{
		connexion = 0;
		return false;
	}

	CAT_FOREVER
	{
		// Grab the slot
		Slot *slot = &_map_table[key];

		Connexion *conn = slot->conn;

		// If the slot is used and the user address matches,
		if (conn && conn->_client_addr == addr)
		{
			conn->AddRef(CAT_REFOBJECT_TRACE);

			connexion = conn;
			return false;
		}
		else
		{
			// If the slot indicates a collision,
			if (slot->collision)
			{
				// Calculate next collision key
				key = (key * COLLISION_MULTIPLIER + COLLISION_INCREMENTER) & HASH_TABLE_MASK;

				// Loop around and process the next slot in the collision list
			}
			else
			{
				// Reached end of collision list, so the address was not found in the table
				break;
			}
		}
	}

	// Do flood key computation only if address is not in the address map table
	u32 flood_key = flood_hash_addr(addr, _flood_salt) & HASH_TABLE_MASK;

	connexion = 0;
	return (_flood_table[flood_key] >= CONNECTION_FLOOD_THRESHOLD);
}

#endif // CAT_SPHYNX_ROAMING_IP

Connexion *ConnexionMap::Lookup(u32 key)
{
#if defined(CAT_SPHYNX_ROAMING_IP)
	if (key >= _map_alloc) return 0;
#else
	if (key >= HASH_TABLE_SIZE) return 0;
#endif

	AutoReadLock lock(_table_lock);

	if (IsShutdown())
		return 0;

#if defined(CAT_SPHYNX_ROAMING_IP)
	Connexion *conn = _conn_table[key];
#else
	Connexion *conn = _map_table[key].conn;
#endif

	if (conn)
	{
		conn->AddRef(CAT_REFOBJECT_TRACE);
		return conn;
	}

	return 0;
}

SphynxError ConnexionMap::Insert(Connexion *conn)
{
#if !defined(CAT_SPHYNX_ROAMING_IP)

	// Hash IP:port:salt to get the hash table key
	u32 key = map_hash_addr(conn->_client_addr, _ip_salt, _port_salt) & HASH_TABLE_MASK;
	u32 flood_key = flood_hash_addr(conn->_client_addr, _flood_salt) & HASH_TABLE_MASK;

	// Grab the slot
	Slot *slot = &_map_table[key];

	// Add a reference to the Connexion
	conn->AddRef(CAT_REFOBJECT_TRACE);

	AutoWriteLock lock(_table_lock);

	if (IsShutdown())
	{
		lock.Release();
		conn->ReleaseRef(CAT_REFOBJECT_TRACE);
		return ERR_SHUTDOWN;
	}

	// While collision keys are marked used,
	while (slot->conn)
	{
		// If client is already connected,
		if (slot->conn->_client_addr == conn->_client_addr)
		{
			lock.Release();
			conn->ReleaseRef(CAT_REFOBJECT_TRACE);
			return ERR_ALREADY_CONN;
		}

		// Set flag for collision
		slot->collision = true;

		// Iterate to next collision key
		key = (key * COLLISION_MULTIPLIER + COLLISION_INCREMENTER) & HASH_TABLE_MASK;
		slot = &_map_table[key];

		// NOTE: This will loop forever if every table key is marked used
	}

	_count++;

	_flood_table[flood_key]++;

	// Mark used
	slot->conn = conn;
	conn->_my_id = key;
	conn->_flood_key = flood_key;

	lock.Release();

#else // Roaming IP version:

	// Hash IP:port:salt to get the hash table key
	u32 flood_key = flood_hash_addr(conn->_client_addr, _flood_salt) & HASH_TABLE_MASK;

	// Add a reference to the Connexion
	conn->AddRef(CAT_REFOBJECT_TRACE);

	AutoWriteLock lock(_table_lock);

	if (IsShutdown())
	{
		lock.Release();
		conn->ReleaseRef(CAT_REFOBJECT_TRACE);
		return ERR_SHUTDOWN;
	}

	// If flood count is above threshold,
	if (_flood_table[flood_key] > CONNECTION_FLOOD_THRESHOLD)
	{
		lock.Release();
		CAT_INFO("ConnexionMap") << "Ignored connexion flood from " << conn->GetAddress().IPToString() << " : " << conn->GetAddress().GetPort();
		conn->ReleaseRef(CAT_REFOBJECT_TRACE);
		return ERR_FLOOD;
	}

	// If no free slots,
	u16 slot_id = _first_free;
	if (slot_id == ConnexionMap::INVALID_KEY)
	{
		// If out of room,
		if (_map_alloc >= MAX_POPULATION)
		{
			lock.Release();
			CAT_INFO("ConnexionMap") << "Cannot accept new connexion from " << conn->GetAddress().IPToString() << " : " << conn->GetAddress().GetPort();
			conn->ReleaseRef(CAT_REFOBJECT_TRACE);
			return ERR_SERVER_FULL;
		}

		// Expand!

		u32 old_alloc = _map_alloc;
		u32 new_alloc = old_alloc * 2;
		if (new_alloc > MAX_POPULATION) new_alloc = MAX_POPULATION;
		else if (new_alloc < MAP_PREALLOC) new_alloc = MAP_PREALLOC;

		// Allocate tables
		Connexion **conn_table;
		do conn_table = new (std::nothrow) Connexion*[new_alloc];
		while (!conn_table);

		u16 *free_table;
		do free_table = new (std::nothrow) u16[new_alloc];
		while (!free_table);

		// Copy old data over
		if (_conn_table) memcpy(conn_table, _conn_table, sizeof(Connexion*) * old_alloc);

		// Clear the new connexion pointers
		memset(conn_table + old_alloc, 0, sizeof(Connexion*) * (new_alloc - old_alloc));

		// Release old tables
		delete []_conn_table;
		delete []_free_table;

		// Replace old table
		_map_alloc = new_alloc;
		_conn_table = conn_table;
		_free_table = free_table;

		// Initialize free list
		_first_free = old_alloc;
		for (u32 ii = old_alloc; ii < new_alloc - 1; ++ii)
			_free_table[ii] = (u16)(ii + 1);
		_free_table[new_alloc - 1] = ConnexionMap::INVALID_KEY;

		// Use the first free slot for the new slot
		slot_id = old_alloc;
	}

	// Set connexion pointer for the slot
	_conn_table[slot_id] = conn;

	// Advance first free index
	_first_free = _free_table[slot_id];

	// Increment population count
	_count++;

	// Increment flood count
	_flood_table[flood_key]++;

	// Set map properties in connexion object
	conn->_my_id = slot_id;
	conn->_flood_key = flood_key;

	lock.Release();

#endif // CAT_SPHYNX_ROAMING_IP

	CAT_INFO("ConnexionMap") << "Inserted connexion from " << conn->GetAddress().IPToString() << " : " << conn->GetAddress().GetPort() << " id=" << conn->GetMyID();

	// Keeps reference held
	return ERR_NO_PROBLEMO;
}

void ConnexionMap::Remove(Connexion *conn)
{
	if (!conn) return;

	u32 key = conn->GetMyID();

	// If key is invalid,
	if (key >= HASH_TABLE_SIZE) return;

	CAT_INFO("ConnexionMap") << "Removing connexion from " << conn->GetAddress().IPToString() << " : " << conn->GetAddress().GetPort() << " id=" << conn->GetMyID();

	u32 flood_key = conn->_flood_key;

	AutoWriteLock lock(_table_lock);

#if !defined(CAT_SPHYNX_ROAMING_IP)

	// Remove connexion
	_map_table[key].conn = 0;

	// If at a leaf in the collision list,
	if (!_map_table[key].collision)
	{
		// Unset collision flags until first filled entry is found
		do 
		{
			// Roll backwards
			key = ((key + COLLISION_INCRINVERSE) * COLLISION_MULTINVERSE) & HASH_TABLE_MASK;

			// If collision list is done,
			if (!_map_table[key].collision)
				break;

			// Remove collision flag
			_map_table[key].collision = false;

		} while (!_map_table[key].conn);
	}

#else

	_conn_table[key] = 0;
	_free_table[key] = _first_free;
	_first_free = key;

#endif // CAT_SPHYNX_ROAMING_IP

	_count--;
	_flood_table[flood_key]--;

	lock.Release();

	// Finally release reference so that it can die
	conn->ReleaseRef(CAT_REFOBJECT_TRACE);
}

void ConnexionMap::ShutdownAll()
{
	CAT_INFO("ConnexionMap") << "Requesting shutdown of all connexions";

	std::vector<Connexion*> connexions;

	AutoWriteLock lock(_table_lock);

	_is_shutdown = true;

#if !defined(CAT_SPHYNX_ROAMING_IP)

	// For each hash table bin,
	for (int key = 0; key < HASH_TABLE_SIZE; ++key)
	{
		Connexion *conn = _map_table[key].conn;

		// If table entry is populated,
		if (conn)
		{
			conn->AddRef(CAT_REFOBJECT_TRACE);
			connexions.push_back(conn);

			_map_table[key].conn = 0;
		}

		_map_table[key].collision = false;
	}

#else

	// For each bin,
	for (u32 key = 0; key < _map_alloc; ++key)
	{
		Connexion *conn = _conn_table[key];

		// If table entry is populated,
		if (conn)
		{
			conn->AddRef(CAT_REFOBJECT_TRACE);
			connexions.push_back(conn);

			_conn_table[key] = 0;
		}
	}

#endif // CAT_SPHYNX_ROAMING_IP

	_count = 0;

	lock.Release();

	// For each Connexion object to release,
	for (u32 ii = 0, size = (u32)connexions.size(); ii < size; ++ii)
	{
		Connexion *conn = connexions[ii];

		conn->Destroy(CAT_REFOBJECT_TRACE);
		conn->ReleaseRef(CAT_REFOBJECT_TRACE);
	}
}
