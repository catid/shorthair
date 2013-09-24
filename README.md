# Shorthair Low-Latency Networking

Shorthair provides channel modeling, security, and low-latency messaging.

It allows you to take any UDP/IP data stream and dial the packet loss rate
down as low as you like, while preventing tampering, and providing live
numbers for loss and latency.

#### In short, it fixes the largest problems with using UDP/IP.

On top of Shorthair you can build any number of other transport protocols
involving ordered-reliable, ordered-unreliable, and unordered-unreliable
combinations.  As a black box you can treat it like normal UDP with some
nice additional features (security, very low loss) as otherwise it works
identically.

#### Remaining problems:

+ Congestion control (CC) is not provided.
+ You can still lose packets (rarely).
+ Packets still arrive out of order.

ARQ can be built effectively on top of Shorthair producing a hybrid that has
very low average latency and guaranteed delivery.  Sending a NACK over the
reverse channel as normal data is an effective way to recover from losses for
full reliability, whereas normal ARQ would suffer from over 2x the normal
packet loss rate to recover from a loss event.

I decided to split the transport layer into shorthair + ARQ/CC since for a
lot of applications like audio streaming, ARQ and CC are not even desired.

