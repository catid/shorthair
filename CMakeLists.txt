cmake_minimum_required(VERSION 3.5)
project(shorthair)

set(CMAKE_CONFIGURATION_TYPES "Debug;Release" CACHE STRING "" FORCE)

set(CMAKE_CXX_STANDARD 11)

set(LIB_SOURCE_FILES
        cauchy_256.cpp
        cauchy_256.h
        Counter.h
        gf256.cpp
        gf256.h
        PacketAllocator.cpp
        PacketAllocator.h
        Shorthair.cpp
        Shorthair.hpp
        ShorthairDetails.hpp
        SiameseTools.cpp
        SiameseTools.h
        )

set(UNIT_TEST_SOURCE_FILES
        tests/Tester.cpp
        )

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()

if(MSVC)
else()
    set(CMAKE_CXX_FLAGS "-Wall -Wextra")
    set(CMAKE_CXX_FLAGS_DEBUG "-g -O0 -march=native")
    set(CMAKE_CXX_FLAGS_RELEASE "-O3 -march=native")
endif()

include_directories(.)

add_library(shorthair STATIC ${LIB_SOURCE_FILES})

add_executable(shorthair_test ${UNIT_TEST_SOURCE_FILES})
target_link_libraries(shorthair_test shorthair)
