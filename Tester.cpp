#include "shorthair/Shorthair.hpp"
using namespace cat;
using namespace shorthair;

#include <iostream>
#include <iomanip>
using namespace std;


class ZeroLossServer : IShorthair {
	// Called with the latest data packet from remote host
	virtual void OnPacket(void *packet, int bytes) {
	}

	// Called with the latest OOB packet from remote host
	virtual void OnOOB(const u8 *packet, int bytes) {
	}

	// Send raw data to remote host over UDP socket
	virtual void SendData(void *buffer, int bytes) {
	}
};

class ZeroLossClient : IShorthair {
	// Called with the latest data packet from remote host
	virtual void OnPacket(void *packet, int bytes) {
	}

	// Called with the latest OOB packet from remote host
	virtual void OnOOB(const u8 *packet, int bytes) {
	}

	// Send raw data to remote host over UDP socket
	virtual void SendData(void *buffer, int bytes) {
	}
};



int main()
{
	ZeroLossClient client;
	ZeroLossServer server;

	return 0;
}


// TODO: Test it!

