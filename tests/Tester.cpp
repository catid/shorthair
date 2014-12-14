#include "Shorthair.hpp"
#include "AbyssinianPRNG.hpp"
using namespace cat;
using namespace shorthair;

#include <iostream>
#include <iomanip>
using namespace std;

//#define SLOW_TESTER

#ifdef SLOW_TESTER
#define TICK_RATE 150
#define PKTS_PER_TICK 1
#define VERBOSE(x) x
#else
#define TICK_RATE 10
#define PKTS_PER_TICK 1
#define VERBOSE(x)
#endif


//// ZeroLoss Classes

class ZeroLossServer;
class ZeroLossClient;

class ZeroLossServer : IShorthair {
	friend class ZeroLossClient;

	u32 _sent;
	Shorthair _codec;
	ZeroLossClient *_client;
    Abyssinian *_prng;
	u32 _next;

	// Called with the latest data packet from remote host
	virtual void OnPacket(u8 *packet, int bytes);

	// Called with the latest OOB packet from remote host
	virtual void OnOOB(u8 *packet, int bytes);

	// Send raw data to remote host over UDP socket
	virtual void SendData(u8 *buffer, int bytes);

public:
	ZeroLossServer() {
		_sent = 0;
		_next = 0;
	}

    void Accept(ZeroLossClient *client, Abyssinian *prng);
	void Tick();
};


class ZeroLossClient : IShorthair {
	friend class ZeroLossServer;

	u32 _received;
	Shorthair _codec;
	ZeroLossServer *_server;
    Abyssinian *_prng;

	// Called with the latest data packet from remote host
	virtual void OnPacket(u8 *packet, int bytes);

	// Called with the latest OOB packet from remote host
	virtual void OnOOB(u8 *packet, int bytes);

	// Send raw data to remote host over UDP socket
	virtual void SendData(u8 *buffer, int bytes);

public:
	ZeroLossClient() {
		_received = 0;
	}

    void Connect(ZeroLossServer *server, Abyssinian *prng);
	void Tick();
};


//// ZeroLossServer

// Called with the latest data packet from remote host
void ZeroLossServer::OnPacket(u8 *packet, int bytes) {
	CAT_EXCEPTION();
}

// Called with the latest OOB packet from remote host
void ZeroLossServer::OnOOB(u8 *packet, int bytes) {
	CAT_EXCEPTION();
}

// Send raw data to remote host over UDP socket
void ZeroLossServer::SendData(u8 *buffer, int bytes) {
	// Simulate loss
	if ((_prng->Next() % 100) < 10) {
		VERBOSE(cout << "RAWR PACKET LOSS -- Dropping packet with bytes = " << bytes << endl);
		return;
	}

	VERBOSE(cout << "TESTER: RAW SEND DATA LEN = " << bytes << endl);

	_client->_codec.Recv(buffer, bytes);
}

void ZeroLossServer::Accept(ZeroLossClient *client, Abyssinian *prng)
{
	_client = client;
	_prng = prng;

	Settings settings;
	settings.target_loss = 0.03;
	settings.max_delay = 100;
	settings.max_data_size = 1350;
	settings.interface = this;
	settings.conserve_bandwidth = true;

	_codec.Initialize(settings);

	_next = 0;
}

void ZeroLossServer::Tick() {
	// Send data at a steady rate

	static const int MAX_SIZE = 1350;
    static const int MIN_SIZE = 4 + 4;
	u8 buffer[MAX_SIZE] = {0};

	// >10 "MBPS" if packet payload is 1350 bytes
	for (int ii = 0; ii < PKTS_PER_TICK; ++ii) {
        Abyssinian prng;
		prng.Initialize(_next);

        int len = (_prng->Next() % (MAX_SIZE - MIN_SIZE + 1)) + MIN_SIZE;

		VERBOSE(cout << "TESTER: SENDING PACKET " << _next << " with len = " << len << endl);

		*(u32*)buffer = _next++;

		*(u32*)(buffer + 4) = len;

		for (int jj = 8; jj < len; ++jj) {
			buffer[jj] = (u8)prng.Next();
		}

		++_sent;
		_codec.Send(buffer, len);
	}

	//cout << ">> Ticking server <<" << endl;
	_codec.Tick();
}


//// ZeroLossClient

// Called with the latest data packet from remote host
void ZeroLossClient::OnPacket(u8 *packet, int bytes) {
	CAT_ENFORCE(bytes >= 8);

	u32 id = *(u32*)packet;
	u32 len = *(u32*)(packet + 4);

	VERBOSE(cout << "TESTER: ON PACKET " << id << " with len = " << len << endl);

	CAT_ENFORCE(bytes == len);

	Abyssinian prng;
	prng.Initialize(id);

	for (int jj = 8; jj < (int)len; ++jj) {
		CAT_ENFORCE(packet[jj] == (u8)prng.Next());
	}

	++_received;
}

// Called with the latest OOB packet from remote host
void ZeroLossClient::OnOOB(u8 *packet, int bytes) {
	CAT_EXCEPTION();
}

// Send raw data to remote host over UDP socket
void ZeroLossClient::SendData(u8 *buffer, int bytes) {
	_server->_codec.Recv(buffer, bytes);
}

void ZeroLossClient::Connect(ZeroLossServer *server, Abyssinian *prng) {
	_server = server;
	_prng = prng;

	Settings settings;
	settings.target_loss = 0.03;
	settings.max_delay = 100;
	settings.max_data_size = 1350;
	settings.conserve_bandwidth = true;
	settings.interface = this;

	_codec.Initialize(settings);

	server->Accept(this, prng);
}

void ZeroLossClient::Tick() {
	//cout << ">> Ticking client <<" << endl;
	_codec.Tick();

	cout << _received << " of " << _server->_sent << " : " << _received / (float)_server->_sent << endl;
}


//// ZeroLossTest

void ZeroLossTest() {
	Clock clock;
	clock.OnInitialize();

	Abyssinian prng;
	prng.Initialize(0);

	ZeroLossClient client;
	ZeroLossServer server;

	// Simulate connection start
	client.Connect(&server, &prng);

	static const int SLEEP_TIME = TICK_RATE; // milliseconds

	for (;;) {
		Clock::sleep(SLEEP_TIME);

		client.Tick();
		server.Tick();
	}

	clock.OnFinalize();
}



int main()
{
	ZeroLossTest();

	return 0;
}

