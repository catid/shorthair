# Change your compiler settings here

# Clang seems to produce faster code
#CCPP = g++
#CC = gcc
#OPTFLAGS = -O3 -fomit-frame-pointer -funroll-loops
CCPP = clang++
CC = clang
OPTFLAGS = -O4 -DCAT_THREADED_ALLOCATOR
DBGFLAGS = -g -O0 -DDEBUG -DCAT_THREADED_ALLOCATOR
CFLAGS = -Wall -fstrict-aliasing -I ./libcat -I ./longhair/include -I ./include
CPFLAGS = $(CFLAGS)
LIBS =


# Object files

libcat_o = EndianNeutral.o Clock.o BitMath.o Enforcer.o \
		   ReuseAllocator.o MemXOR.o MemSwap.o Mutex.o
longhair_o = cauchy_256.o
shorthair_o = Shorthair.o $(longhair_o)
tester_o = Tester.o $(shorthair_o) $(libcat_o) MersenneTwister.o SecureEqual.o
redundancy_o = Redundancy.o $(libcat_o)


# Release target (default)

release : CFLAGS += $(OPTFLAGS)
release : tester


# Debug target

debug : CFLAGS += $(DBGFLAGS) -DCAT_DUMP_SHORTHAIR
debug : tester


# tester executable

tester : CFLAGS += -DCAT_CLOCK_EXTRA
tester : clean $(tester_o)
	$(CCPP) $(LIBS) -o tester $(tester_o)


# Valgrind tester executable

valgrind : debug
	$(CCPP) $(LIBS) -o tester $(tester_o)
	valgrind --dsymutil=yes ./tester


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

Mutex.o : libcat/Mutex.cpp
	$(CCPP) $(CFLAGS) -c libcat/Mutex.cpp

MemSwap.o : libcat/MemSwap.cpp
	$(CCPP) $(CFLAGS) -c libcat/MemSwap.cpp

Enforcer.o : libcat/Enforcer.cpp
	$(CCPP) $(CPFLAGS) -c libcat/Enforcer.cpp

EndianNeutral.o : libcat/EndianNeutral.cpp
	$(CCPP) $(CPFLAGS) -c libcat/EndianNeutral.cpp

ReuseAllocator.o : libcat/ReuseAllocator.cpp
	$(CCPP) $(CPFLAGS) -c libcat/ReuseAllocator.cpp

SecureEqual.o : libcat/SecureEqual.cpp
	$(CCPP) $(CPFLAGS) -c libcat/SecureEqual.cpp


# Longhair objects

cauchy_256.o : longhair/src/cauchy_256.cpp
	$(CCPP) $(CFLAGS) -c longhair/src/cauchy_256.cpp



# Shorthair objects

Shorthair.o : src/Shorthair.cpp
	$(CCPP) $(CPFLAGS) -c src/Shorthair.cpp


# Cleanup

.PHONY : clean

clean :
	git submodule update --init --recursive
	-rm redtest tester *.o

