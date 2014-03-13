# Change your compiler settings here

# Clang seems to produce faster code
#CCPP = g++
#CC = gcc
#OPTFLAGS = -O3 -fomit-frame-pointer -funroll-loops
CCPP = clang++
CC = clang
OPTFLAGS = -O4
DBGFLAGS = -g -O0 -DDEBUG
CFLAGS = -Wall -fstrict-aliasing -I ./libcat -I ./longhair/include -I ./include
CPFLAGS = $(CFLAGS)
LIBS =


# Multi-threaded version avoids large latency spikes in encoder/decoder processing


# Object files

libcat_o = EndianNeutral.o Clock.o BitMath.o Enforcer.o \
		   ReuseAllocator.o MemXOR.o SecureErase.o
longhair_o = cauchy_256.o
shorthair_o = Shorthair.o $(longhair_o)
tester_o = Tester.o $(shorthair_o) $(libcat_o) MersenneTwister.o
redundancy_o = Redundancy.o $(libcat_o)


# Release target (default)

release : CFLAGS += $(OPTFLAGS)
release : tester


# Debug target

debug : CFLAGS += $(DBGFLAGS)
debug : tester


# tester executable

tester : CFLAGS += -DCAT_CLOCK_EXTRA
tester : $(tester_o)
	$(CCPP) $(LIBS) -o tester $(tester_o)


# redundancy executable

redtest : CFLAGS += $(DBGFLAGS)
redtest : $(redundancy_o)
	$(CCPP) -o redtest $(redundancy_o)


# Test objects

Tester.o : tests/Tester.cpp
	$(CCPP) $(CPFLAGS) -c tests/Tester.cpp

Redundancy.o : tests/Redundancy.cpp
	$(CCPP) $(CPFLAGS) -c tests/Redundancy.cpp


# LibCat objects

MersenneTwister.o : libcat/MersenneTwister.cpp
	$(CCPP) $(CPFLAGS) -c libcat/MersenneTwister.cpp

Clock.o : libcat/Clock.cpp
	$(CCPP) $(CFLAGS) -c libcat/Clock.cpp

BitMath.o : libcat/BitMath.cpp
	$(CCPP) $(CFLAGS) -c libcat/BitMath.cpp

MemXOR.o : libcat/MemXOR.cpp
	$(CCPP) $(CFLAGS) -c libcat/MemXOR.cpp

MemSwap.o : libcat/MemSwap.cpp
	$(CCPP) $(CFLAGS) -c libcat/MemSwap.cpp

Enforcer.o : libcat/Enforcer.cpp
	$(CCPP) $(CPFLAGS) -c libcat/Enforcer.cpp

EndianNeutral.o : libcat/EndianNeutral.cpp
	$(CCPP) $(CPFLAGS) -c libcat/EndianNeutral.cpp

ReuseAllocator.o : libcat/ReuseAllocator.cpp
	$(CCPP) $(CPFLAGS) -c libcat/ReuseAllocator.cpp


# Longhair objects

cauchy_256.o : longhair/src/cauchy_256.cpp
	$(CCPP) $(CFLAGS) -c longhair/src/cauchy_256.cpp



# Shorthair objects

Shorthair.o : shorthair/Shorthair.cpp
	$(CCPP) $(CPFLAGS) -c shorthair/Shorthair.cpp


# Cleanup

.PHONY : clean

clean :
	-rm redtest tester *.o

