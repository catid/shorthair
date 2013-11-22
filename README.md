# Shorthair Low-Latency Networking

The Shorthair library uses Calico and Wirehair to provide low-latency loss-prevention and data integrity, which uses extra bandwidth to make almost any unreliable packet channel suitable for real-time communication.

#### Pros:

+ Two-way communication over a single lossy channel.

+ You can dial the packet loss to any acceptable rate for your application.

+ It has a RTT*3/2 upper-bound delay for the data it protects, which is the lower-bound for recovering data with ARQ.

+ Calculates and generates precisely the amount of redundancy required to achieve the target loss rate.

+ It supports variable-length data packets.

+ Overhead is 16 bytes/packet.

+ Provides data encryption and integrity validation.

+ Redundant packets are 18 bytes + size of largest packet in the code group.

+ Ruthlessly-optimized multi-threaded software.

+ Library has a clean platform-independent interface with minimal configuration required.

#### Cons:

- Congestion control/avoidance is not provided.

- It doesn't handle re-ordering.

- It doesn't guarantee delivery of your data.

#### In short, it solves the hardest problems of using UDP/IP.

### Applications

On top of Shorthair you can build any number of other transport protocols
involving ordered-reliable, ordered-unreliable, and unordered-unreliable
combinations.  As a black box you can treat it like normal UDP with some
nice additional features (security, very low loss) as otherwise it works
identically.

ARQ can be built effectively on top of Shorthair producing a hybrid that has
very low average latency and guaranteed delivery.  Sending a NACK over the
reverse channel as normal data is an effective way to recover from losses for
full reliability, whereas normal ARQ would suffer from over 2x the normal
packet loss rate to recover from a loss event.

Also consider a broadcast scenario with many receivers, where the loss rate
is mulitplied by N.  Someone out there is going to have a bad time every
time a new message is rebroadcast.

I decided to split the transport layer into shorthair + ARQ/CC since for a
lot of applications like audio streaming, ARQ and CC are not even desired.

