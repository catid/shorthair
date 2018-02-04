#include "../Shorthair.hpp"
using namespace cat;
using namespace shorthair;

#include <iostream>
#include <iomanip>
#include <thread>
#include <chrono>
using namespace std;

//#define SLOW_TESTER

#ifdef SLOW_TESTER
#define TICK_RATE 150
#define PKTS_PER_TICK 1
#define VERBOSE(x) x
#else
#define TICK_RATE 5
#define PKTS_PER_TICK 10
#define VERBOSE(x)
#endif

#define ENABLE_PACKETLOSS 0.1f


//// ZeroLoss Classes

class ZeroLossServer;
class ZeroLossClient;

class ZeroLossServer : IShorthair {
    friend class ZeroLossClient;

    uint32_t _sent;
    ShorthairCodec _codec;
    ZeroLossClient *_client;
    siamese::PCGRandom* _prng;
    uint32_t _next;

    // Called with the latest data packet from remote host
    virtual void OnPacket(uint8_t *packet, int bytes);

    // Called with the latest OOB packet from remote host
    virtual void OnOOB(uint8_t *packet, int bytes);

    // Send raw data to remote host over UDP socket
    virtual void SendData(uint8_t *buffer, int bytes);

public:
    ZeroLossServer() {
        _sent = 0;
        _next = 0;
    }

    void Accept(ZeroLossClient *client, siamese::PCGRandom *prng);
    void Tick();
};


class ZeroLossClient : IShorthair {
    friend class ZeroLossServer;

    uint32_t _received;
    ShorthairCodec _codec;
    ZeroLossServer *_server;
    siamese::PCGRandom *_prng;

    // Called with the latest data packet from remote host
    virtual void OnPacket(uint8_t *packet, int bytes);

    // Called with the latest OOB packet from remote host
    virtual void OnOOB(uint8_t *packet, int bytes);

    // Send raw data to remote host over UDP socket
    virtual void SendData(uint8_t *buffer, int bytes);

public:
    ZeroLossClient() {
        _received = 0;
    }

    void Connect(ZeroLossServer *server, siamese::PCGRandom *prng);
    void Tick();
};


//// ZeroLossServer

// Called with the latest data packet from remote host
void ZeroLossServer::OnPacket(uint8_t *packet, int bytes) {
    SIAMESE_DEBUG_BREAK(); // Unused
}

// Called with the latest OOB packet from remote host
void ZeroLossServer::OnOOB(uint8_t *packet, int bytes) {
    SIAMESE_DEBUG_BREAK(); // Unused
}

// Send raw data to remote host over UDP socket
void ZeroLossServer::SendData(uint8_t *buffer, int bytes) {
#ifdef ENABLE_PACKETLOSS
    const float minimumPLR = ENABLE_PACKETLOSS;
    const uint32_t thresh = (uint32_t)(0xffffffff * minimumPLR);

    // Simulate loss
    if (_prng->Next() < thresh) {
        VERBOSE(cout << "RAWR PACKET LOSS -- Dropping packet with bytes = " << bytes << endl);
        return;
    }
#endif

    VERBOSE(cout << "TESTER: RAW SEND DATA LEN = " << bytes << endl);

    _client->_codec.Recv(buffer, bytes);
}

void ZeroLossServer::Accept(ZeroLossClient *client, siamese::PCGRandom *prng)
{
    _client = client;
    _prng = prng;

    Settings settings;
    settings.min_fec_overhead = 0.2f;
    settings.max_delay = 100;
    settings.max_data_size = 1350;
    settings.interface_ptr = this;

    _codec.Initialize(settings);

    _next = 0;
}

void ZeroLossServer::Tick() {
    // Send data at a steady rate

    static const int MAX_SIZE = 1350;
    static const int MIN_SIZE = 4 + 4;
    uint8_t buffer[MAX_SIZE] = {0};

    // >10 "MBPS" if packet payload is 1350 bytes
    for (int ii = 0; ii < PKTS_PER_TICK; ++ii) {
        siamese::PCGRandom prng;
        prng.Seed(_next);

        int len = (_prng->Next() % (MAX_SIZE - MIN_SIZE + 1)) + MIN_SIZE;

        VERBOSE(cout << "TESTER: SENDING PACKET " << _next << " with len = " << len << endl);

        *(uint32_t*)buffer = _next++;

        *(uint32_t*)(buffer + 4) = len;

        for (int jj = 8; jj < len; ++jj) {
            buffer[jj] = (uint8_t)prng.Next();
        }

        ++_sent;
        _codec.Send(buffer, len);
    }

    //cout << ">> Ticking server <<" << endl;
    _codec.Tick();
}


//// ZeroLossClient

// Called with the latest data packet from remote host
void ZeroLossClient::OnPacket(uint8_t *packet, int bytes) {
    SIAMESE_DEBUG_ASSERT(bytes >= 8);

    uint32_t id = *(uint32_t*)packet;
    uint32_t len = *(uint32_t*)(packet + 4);

    VERBOSE(cout << "TESTER: ON PACKET " << id << " with len = " << len << endl);

    SIAMESE_DEBUG_ASSERT(bytes == len);

    siamese::PCGRandom prng;
    prng.Seed(id);

    for (int jj = 8; jj < (int)len; ++jj) {
        SIAMESE_DEBUG_ASSERT(packet[jj] == (uint8_t)prng.Next());
    }

    ++_received;
}

// Called with the latest OOB packet from remote host
void ZeroLossClient::OnOOB(uint8_t *packet, int bytes) {
    SIAMESE_DEBUG_BREAK(); // Unused
}

// Send raw data to remote host over UDP socket
void ZeroLossClient::SendData(uint8_t *buffer, int bytes) {
    _server->_codec.Recv(buffer, bytes);
}

void ZeroLossClient::Connect(ZeroLossServer *server, siamese::PCGRandom *prng) {
    _server = server;
    _prng = prng;

    Settings settings;
    settings.min_fec_overhead = 0.2f;
    settings.max_delay = 100;
    settings.max_data_size = 1400;
    settings.interface_ptr = this;

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
    siamese::PCGRandom prng;
    prng.Seed(0);

    ZeroLossClient client;
    ZeroLossServer server;

    // Simulate connection start
    client.Connect(&server, &prng);

    for (;;) {
        std::this_thread::sleep_for(std::chrono::milliseconds(TICK_RATE));

        client.Tick();
        server.Tick();
    }
}



int main()
{
    ZeroLossTest();

    return 0;
}

