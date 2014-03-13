# Change your compiler settings here

# Clang seems to produce faster code
#CCPP = g++
#CC = gcc
#OPTFLAGS = -O3 -fomit-frame-pointer -funroll-loops
CCPP = clang++
CC = clang
OPTFLAGS = -O4
DBGFLAGS = -g -O0 -DDEBUG
CFLAGS = -Wall -fstrict-aliasing -I ./libcat -I ./longhair/include
CPFLAGS = $(CFLAGS)
LIBS = -lpthread


# Multi-threaded version avoids large latency spikes in encoder/decoder processing


# Object files

mt_o = Mutex.o Thread.o
libcat_o = EndianNeutral.o Clock.o MersenneTwister.o BitMath.o Enforcer.o \
		   ReuseAllocator.o MemXOR.o SecureErase.o
calico_o = AntiReplayWindow.o Calico.o ChaChaVMAC.o Skein.o Skein256.o VHash.o
wirehair_o = Wirehair.o
shorthair_o = Shorthair.o ShorthairAPI.o $(wirehair_o) $(calico_o)
tester_o = Tester.o $(shorthair_o) $(libcat_o) $(mt_o)
server_o = Server.o $(shorthair_o) $(libcat_o) $(mt_o)
redundancy_o = Redundancy.o $(libcat_o)


# Release target (default)

release : CFLAGS += $(OPTFLAGS)
release : tester


# Debug target

debug : CFLAGS += $(DBGFLAGS)
debug : tester


# Library.ARM target

library.arm : CCPP = /Volumes/casedisk/prefix/bin/arm-unknown-eabi-g++
library.arm : CPLUS_INCLUDE_PATH = /Volumes/casedisk/prefix/arm-unknown-eabi/include
library.arm : CC = /Volumes/casedisk/prefix/bin/arm-unknown-eabi-gcc
library.arm : C_INCLUDE_PATH = /Volumes/casedisk/prefix/arm-unknown-eabi/include
library.arm : library


# Library target

library : CFLAGS += -O3 -fomit-frame-pointer -funroll-loops -D_POSIX_THREADS
library : $(shorthair_o) $(libcat_o)
	ar rcs libshorthair.a $(shorthair_o) $(libcat_o)


# Server target

server : CFLAGS += $(OPTFLAGS)
server : LIBS += -luv
server : $(server_o)
	$(CCPP) $(LIBS) -o server $(server_o)


# tester executable

tester : CFLAGS += -DCAT_CLOCK_EXTRA
tester : $(tester_o)
	$(CCPP) $(LIBS) -o tester $(tester_o)


# tester objects

Tester.o : Tester.cpp
	$(CCPP) $(CPFLAGS) -c Tester.cpp


# redundancy executable

redtest : CFLAGS += $(DBGFLAGS)
redtest : $(redundancy_o)
	$(CCPP) -o redtest $(redundancy_o)


# redundancy objects

Redundancy.o : Redundancy.cpp
	$(CCPP) $(CPFLAGS) -c Redundancy.cpp


# LibCat objects

Clock.o : libcat/Clock.cpp
	$(CCPP) $(CFLAGS) -c libcat/Clock.cpp

BitMath.o : libcat/BitMath.cpp
	$(CCPP) $(CFLAGS) -c libcat/BitMath.cpp

MemXOR.o : libcat/MemXOR.cpp
	$(CCPP) $(CFLAGS) -c libcat/MemXOR.cpp

MemSwap.o : libcat/MemSwap.cpp
	$(CCPP) $(CFLAGS) -c libcat/MemSwap.cpp


# Library objects

cauchy_256.o : longhair/src/cauchy_256.cpp
	$(CCPP) $(CFLAGS) -c longhair/src/cauchy_256.cpp


# Multi-threading libcat objects

Mutex.o : libcat/Mutex.cpp
	$(CCPP) $(CPFLAGS) -c libcat/Mutex.cpp

Thread.o : libcat/Thread.cpp
	$(CCPP) $(CPFLAGS) -c libcat/Thread.cpp


# Shared objects

MersenneTwister.o : libcat/MersenneTwister.cpp
	$(CCPP) $(CPFLAGS) -c libcat/MersenneTwister.cpp

BitMath.o : libcat/BitMath.cpp
	$(CCPP) $(CPFLAGS) -c libcat/BitMath.cpp

EndianNeutral.o : libcat/EndianNeutral.cpp
	$(CCPP) $(CPFLAGS) -c libcat/EndianNeutral.cpp

Clock.o : libcat/Clock.cpp
	$(CCPP) $(CPFLAGS) -c libcat/Clock.cpp

Enforcer.o : libcat/Enforcer.cpp
	$(CCPP) $(CPFLAGS) -c libcat/Enforcer.cpp

ReuseAllocator.o : libcat/ReuseAllocator.cpp
	$(CCPP) $(CPFLAGS) -c libcat/ReuseAllocator.cpp

MemXOR.o : libcat/MemXOR.cpp
	$(CCPP) $(CPFLAGS) -c libcat/MemXOR.cpp

SecureErase.o : libcat/SecureErase.cpp
	$(CCPP) $(CPFLAGS) -c libcat/SecureErase.cpp


# Wirehair objects

Wirehair.o : wirehair/Wirehair.cpp
	$(CCPP) $(CPFLAGS) -c wirehair/Wirehair.cpp


# Calico objects

AntiReplayWindow.o : calico/AntiReplayWindow.cpp
	$(CCPP) $(CPFLAGS) -c calico/AntiReplayWindow.cpp

Calico.o : calico/Calico.cpp
	$(CCPP) $(CPFLAGS) -c calico/Calico.cpp

ChaChaVMAC.o : calico/ChaChaVMAC.cpp
	$(CCPP) $(CPFLAGS) -c calico/ChaChaVMAC.cpp

Skein.o : calico/Skein.cpp
	$(CCPP) $(CPFLAGS) -c calico/Skein.cpp

Skein256.o : calico/Skein256.cpp
	$(CCPP) $(CPFLAGS) -c calico/Skein256.cpp

VHash.o : calico/VHash.cpp
	$(CCPP) $(CPFLAGS) -c calico/VHash.cpp


# Shorthair objects

Shorthair.o : shorthair/Shorthair.cpp
	$(CCPP) $(CPFLAGS) -c shorthair/Shorthair.cpp

ShorthairAPI.o : shorthair/ShorthairAPI.cpp
	$(CCPP) $(CPFLAGS) -c shorthair/ShorthairAPI.cpp


# Server objects

Server.o : Server.cpp
	$(CCPP) $(CPFLAGS) -c Server.cpp


# Cleanup

.PHONY : clean

clean :
	-rm tester $(tester_o)

