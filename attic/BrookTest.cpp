#include "wirehair/Wirehair.hpp"
#include "calico/Calico.hpp"
#include "Clock.hpp"
#include "Delegates.hpp"
#include "MersenneTwister.hpp"
#include "Enforcer.hpp"
using namespace cat;

#include <iostream>
#include <iomanip>
#include <fstream>
#include <cmath>
using namespace std;

static Clock m_clock;












































static const int PASSWORD_KEY_BYTES = 32;	// 256-bit key
static const int SECRET_KEY_BYTES = 32;		// 256-bit key
static const int SEED = 0;					// RNG seed for repeatability
static const float DROP_PERCENTAGE = 12;	// %
static const float LAG_AVG = 2100;			// 200 ms rough center of lag distribution
static const float LAG_TWO_SIG = 500;		// 95% region
static const float LAG_MIN = 1900;			// Cannot be faster than 190 ms
static const int PPS_MAX = 1000;			// 1000 * 1400 = 1.4 MB/s limit
static const int UDP_PAYLOAD = 1441;		// Bytes
static const int SELECTED_MTU = 1430;		// MTU limit
static const int SILENCE_TIMEOUT = 20000;	// 20 seconds
static const int RETRY_INTERVAL = 1000;		// 1 seconds between connect attempt
static const int MAX_PAYLOAD_LIMIT = UDP_PAYLOAD; // Server limit on client request
static const int DATA_RATE = 10;			// Send data every 10 ms
static const int DATA_SIZE = 5000;			// Size of RF data to send every 10 ms


struct Packet {
	u32 trigger;

	u8 buffer[UDP_PAYLOAD];
	int buffer_len;

	Packet *next;
};




class SimulationClock {
	u32 _ms;		// Simulation clock ms

public:
	void Initialize() {
		_ms = 0;
	}

	CAT_INLINE u32 GetTime() {
		return _ms;
	}

	CAT_INLINE void Increment(u32 x) {
		_ms += x;
	}
};


// Event-driven one-way channel simulator
// Attempt at realistic latency
// Uniformly distributed packetloss

// TODO: Some realism: Sending/receiving a packet takes about 1 ms

// void OnPacket(Packet *p);
typedef Delegate1<void, Packet *> PacketDelegate;

class Channel {
	MersenneTwister _rng;		// RNG

	float _drop_rate;			// Ploss [0..1]

	float _lag_min;				// ms
	float _lag_avg; 			// ms
	float _lag_sig;	 			// sigma = sqrt(variance), 2sigma = 95% confidence interval

	int _pps_max;				// Limit on PPS, after that packets get dropped
	int _pps_acc;				// Accumulator for PPS
	u32 _pps_reset;				// Next PPS reset

	u32 _ms;					// Simulation time (ms)
	PacketDelegate _delegate;

	Packet *_head, *_tail;

	bool DropPacket() {
		return _rng.Uni() < _drop_rate;
	}

	u32 NextDelay() { // ms
		// Based on http://www.ieee-infocom.org/2004/papers/37_4.pdf
		float x = _rng.Nor() * _lag_sig + _lag_avg;
		if (x < _lag_min) {
			x = _lag_min;
		}
		return (u32)x;
	}

public:
	void Initialize(u32 seed, float drop_percentage, float lag_avg, float lag_two_sig, float lag_min, int pps_max, PacketDelegate delegate) {
		_rng.Initialize(seed);

		_drop_rate = drop_percentage / 100.f;

		_lag_avg = lag_avg;
		_lag_sig = lag_two_sig / 2.f;
		_lag_min = lag_min;

		_pps_max = pps_max;
		_pps_acc = 0;
		_pps_reset = 1000;

		_ms = 0;
		_delegate = delegate;
		_head = _tail = 0;
	}

	// Advance the simulation ahead to the given number of ms and dequeue any events that occurred
	void AdvanceSimulation(u32 ms) {
		_ms = ms;

		// Peel off expired messages
		Packet *next = _head;
		for (Packet *p = next; p && p->trigger >= ms; p = next) {
			next = p->next;
			_delegate(p);
		}
		_head = next;
		if (!next) {
			_tail = 0;
		}

		// Reset PPS limit (channel bandwidth)
		if (ms >= _pps_reset) {
			_pps_acc = 0;
			_pps_reset = ms + 1000;
		}
	}

	// Free a packet
	void FreePacket(Packet *p) {
		// TODO: Optimize with a custom memory allocator
		delete p;
	}

	// Get a new packet buffer with a prescribed delivery time
	// Or returns null when a packet got dropped
	Packet *NextPacket() {
		// If a packet got dropped,
		if (DropPacket()) {
			// Return null
			return 0;
		}

		// If channel capacity exceeded,
		if (_pps_acc > _pps_max) {
			cout << "WARN: Dropped packet due to channel capacity exceeded" << endl;
			return 0;
		}
		++_pps_acc;

		// TODO: Optimize with a custom memory allocator
		Packet *np = new Packet;

		u32 trigger = _ms + NextDelay();
		np->trigger = trigger;

		// If should be added after tail,
		Packet *prev = 0;
		if (_tail && trigger < _tail->trigger) {
			for (Packet *p = _head; p; prev = p, p = p->next) {
				if (trigger < p->trigger) {
					if (prev) {
						prev->next = np;
					} else {
						_head = np;
					}
					np->next = p;
					return np;
				}
			}
		} else {
			prev = _tail;
		}

		if (prev) {
			prev->next = np;
		} else {
			_head = np;
		}
		np->next = 0;
		_tail = np;
		return np;
	}
};


/*
 * Protocol:
 *
 * Over unreliable UDP channel:
 *
 * c2s ENCRYPTED: 00 "BROOK"(5 B) PASSWORD(32 B) : Connect Request (Timeout = 20 seconds, retry every 1 second)
 * s2c ENCRYPTED: 01 : Acknowledge Connection (Not retried)
 * s2c ENCRYPTED: 02 : Key mismatch (Not retried)
 * c2s ENCRYPTED: 03 MTU(2 B) : Start Data (Timeout = 20 seconds, retry every 1 second)
 * s2c ENCRYPTED: 04 DATA(MTU B) : Data chunk
 * c2s ENCRYPTED: 05 LOSS(2 B) : Feedback about loss rate (Sync every 1 second)
 *
 * Each encrypted data chunk is tagged with an incrementing IV that starts at 0
 */


enum BrookPacketTypes {
	C2S_CONNECT,
	S2C_ACCEPT,
	S2C_FAIL,
	C2S_START,
	S2C_DATA,
	C2S_SYNC
};


enum BrookDiscoReasons {
	DISCO_TIMEOUT,
	DISCO_DENIED
};

static const char *GetDiscoReasonString(int reason) {
	switch (reason) {
	case DISCO_TIMEOUT: return "TIMEOUT";
	case DISCO_DENIED: return "DENIED";
	default: return "(unknown)";
	}
}


/*
 * Source periodically sends RF data packet stream to a single sink
 */

struct SourceSettings {
	u16 max_payload_limit;
	u32 silence_limit;
	u32 tick_ms;
	u32 data_per_tick;
};

class BrookSource {
	u8 _password_key[PASSWORD_KEY_BYTES];
	SimulationClock *_clock;
	Channel *_uplink;
	calico::Calico _cipher;
	u32 _last_packet;
	bool _connected;
	bool _dead;
	u16 _payload_limit;
	SourceSettings _settings;
	bool _sending;

	void Cleanup() {
		_connected = false;
		_last_packet = 0;
		_sending = false;
	}

	void GenerateRFPacket() {
		Packet *p = _uplink->NextPacket();
		if (p) {
			p->buffer[0] = S2C_DATA;
			// TODO
		}
	}

	void OnConnectRequest(u8 *buffer, int len) {
		cout << "Source : Connected!" << endl;

	}

	void OnRepeatConnectRequest() {
		cout << "Source : Repeat Connect Request From Same Tunnel" << endl;

	}

	void OnDataStartRequest(u8 *buffer, int len) {
		cout << "Source : Data Start Request!" << endl;

		// TODO
		u16 mtu;

		CAT_ENFORCE(mtu > calico::Calico::OVERHEAD);

		_payload_limit = mtu - calico::Calico::OVERHEAD;

	}

	void OnDisconnect(int reason) {
		cout << "Source : Disconnected! Reason = " << GetDiscoReasonString(reason) << " ( " << reason << " ) " << endl;

		Cleanup();

		_dead = true;
	}

public:
	void Initialize(SimulationClock *clock, Channel *channel, u8 secret_key[SECRET_KEY_BYTES], u8 password_key[PASSWORD_KEY_BYTES], SourceSettings &settings) {
		_clock = clock;
		_uplink = channel;
		_settings = settings;
		memcpy(_password_key, password_key, sizeof(_password_key));

		Cleanup();

		_cipher.Initialize(secret_key, "BROOK", calico::RESPONDER);

		_dead = false;
	}

	void OnTick() {
		if (_dead) return;

		u32 ms = _clock->GetTime();

		// Verify connexion is live
		if (_connected) {
			if (ms - _last_packet > _settings.silence_limit) {
				OnDisconnect(DISCO_TIMEOUT);
				return;
			}
		}

		if (_sending) {
		}
	}

	void OnPacket(Packet *p) {
		if (_dead) return;

		u64 message_iv;
		int len = _cipher.Decrypt(p->buffer, p->buffer_len, message_iv);

		CAT_ENFORCE(len > 0);

		if (_connected) {
			switch (p->buffer[0]) {
			case C2S_START:
				OnDataStartRequest(p->buffer, p->buffer_len);
				break;
			case C2S_CONNECT:
				OnRepeatConnectRequest();
				break;
			default:
				cout << "Source : Got packet " << (int)p->buffer[0] << " while connected" << endl;
			}
		} else {
			switch (p->buffer[0]) {
			case C2S_CONNECT:
				OnConnectRequest(p->buffer, p->buffer_len);
				break;
			default:
				cout << "Source : Got packet " << (int)p->buffer[0] << " while connected" << endl;
			}
		}
	}
};

/*
 * Continuously estimates latency
 */

struct SinkSettings {
	u16 mtu;
	u32 silence_timeout, retry_interval;
};

class BrookSink {
	u8 _password_key[PASSWORD_KEY_BYTES];
	SimulationClock *_clock;
	Channel *_uplink;
	calico::Calico _cipher;
	u32 _last_packet;
	SinkSettings _settings;
	bool _connected;
	bool _dead;

	void Cleanup() {
		_connected = false;
		_last_packet = 0;
	}

	void SendConnectRequest() {
		cout << "Sink : Sending Connect Request" << endl;

		Packet *p = _uplink->NextPacket();
		if (p) {
			p->buffer[0] = C2S_CONNECT;
			p->buffer[1] = 'B';
			p->buffer[2] = 'R';
			p->buffer[3] = 'O';
			p->buffer[4] = 'O';
			p->buffer[5] = 'K';
			memcpy(p->buffer + 1 + 5, _password_key, sizeof(_password_key));

			p->buffer_len = _cipher.Encrypt(p->buffer, 1 + 5 + sizeof(_password_key), p->buffer, sizeof(p->buffer));
		}
	}

	void OnConnect() {
		cout << "Sink : Connected!" << endl;

	}

	void OnDisconnect() {
		cout << "Sink : Disconnected!" << endl;

		Cleanup();

		_dead = true;
	}

	void OnData(u8 *buffer, int len, u64 iv) {
		cout << "Sink : Got data!" << endl;
	}

public:
	void Initialize(SimulationClock *clock, Channel *channel, u8 secret_key[SECRET_KEY_BYTES], u8 password_key[PASSWORD_KEY_BYTES], SinkSettings &settings) {
		_clock = clock;
		_uplink = channel;
		_settings = settings;
		memcpy(_password_key, password_key, sizeof(_password_key));

		Cleanup();

		_cipher.Initialize(secret_key, "BROOK", calico::INITIATOR);

		_dead = false;
	}

	void OnTick() {
		if (_dead) return;

		if (_connected) {
		} else {
			// Keep sending connection request until timeout
		}
	}

	void OnPacket(Packet *p) {
		if (_dead) return;

		u64 message_iv;
		int len = _cipher.Decrypt(p->buffer, p->buffer_len, message_iv);

		CAT_ENFORCE(len > 0);

		if (_connected) {
			switch (p->buffer[0]) {
			case S2C_DATA:
				OnData(p->buffer, p->buffer_len, message_iv);
				break;
			default:
				cout << "Sink : Got packet " << (int)p->buffer[0] << " while connected" << endl;
			}
		} else {
			switch (p->buffer[0]) {
			case S2C_ACCEPT:
				OnConnect();
				break;
			case S2C_FAIL:
				OnDisconnect(DISCO_DENIED);
				break;
			default:
				cout << "Sink : Got packet " << (int)p->buffer[0] << " while connected" << endl;
			}
		}
	}
};



/*
 * Bandwidth limit
 *
 * Use minimal additional overhead via FEC to reduce the loss rate from input
 * packet loss rate to a selectable real loss rate.
 */

class Simulation {
	SimulationClock _clock;

	Channel _c2s, _s2c;			// Channels
	BrookSource _src;			// Source of RF data
	BrookSink _sink;			// Sink for RF data

	void OnC2S(Packet *p) {
		_src.OnPacket(p);
	}

	void OnS2C(Packet *p) {
		_sink.OnPacket(p);
	}

public:
	void Initialize(u32 seed, float drop_percentage, float lag_avg, float lag_two_sig, float lag_min, int pps_max) {
		_clock.Initialize();

		_c2s.Initialize(seed, drop_percentage, lag_avg, lag_two_sig, lag_min, pps_max,
				PacketDelegate::FromMember<Simulation, &Simulation::OnC2S>(this));
		_s2c.Initialize(seed + 1234, drop_percentage, lag_avg, lag_two_sig, lag_min, pps_max,
				PacketDelegate::FromMember<Simulation, &Simulation::OnS2C>(this));

		// TODO: At some point, a key agreement protocol should be added to exchange the random session private key.
		// Since that is a lot of additional details that are not really useful for evaluating the protocol,
		// I've selected a random key that both sides have magically agreed on here:

		u8 secret_key[32]; // for the session, changes each time

		// Pick the same "random" key each time for reproducibility
		MersenneTwister prng;
		prng.Initialize(seed + 2000);
		prng.Generate(secret_key, sizeof(secret_key));

		u8 password_key[32]; // fixed forever, like a password to access the system

		// Pick the same "random" key each time for reproducibility
		prng.Generate(password_key, sizeof(password_key));

		SourceSettings so;
		so.max_payload_limit = MAX_PAYLOAD_LIMIT;
		so.tick_ms = DATA_RATE;
		so.data_per_tick = DATA_SIZE;
		so.silence_limit = SILENCE_TIMEOUT;

		_src.Initialize(&_clock, &_s2c, secret_key, password_key);

		SinkSettings ss;
		ss.mtu = SELECTED_MTU;
		ss.silence_timeout = SILENCE_TIMEOUT;
		ss.retry_interval = RETRY_INTERVAL;

		_sink.Initialize(&_clock, &_c2s, secret_key, password_key, ss);
	}

	void Tick() {
		// Tick simulation at 5 ms rate, staggering events
		_src.OnTick();
		_sink.OnTick();

		_clock.Increment(2);

		_s2c.AdvanceSimulation(_clock.GetTime());

		_clock.Increment(3);

		_c2s.AdvanceSimulation(_clock.GetTime());
	}
};












int main()
{
	MersenneTwister::InitializeNor();
	MersenneTwister::InitializeExp();
	m_clock.OnInitialize();

	Simulation sim;
	sim.Initialize(SEED, DROP_PERCENTAGE, LAG_AVG, LAG_TWO_SIG, LAG_MIN, PPS_MAX);

	for (;;) {
		sim.Tick();
	}

	m_clock.OnFinalize();

	return 0;
}


