#********************************************************************************
# Makefile for the libsnark library.
#********************************************************************************
#* @author     This file is part of libsnark, developed by SCIPR Lab
#*             and contributors (see AUTHORS).
#* @copyright  MIT license (see LICENSE file)
#*******************************************************************************/

# To override these, use "make OPTFLAGS=..." etc.
CURVE = BN128
OPTFLAGS = -O2 -march=native -mtune=native
FEATUREFLAGS = -DUSE_ASM -DMONTGOMERY_OUTPUT -DDEBUG
CXX = g++

INSTALL_PATH = /usr/local
# Initialize this using "CXXFLAGS=... make". The makefile appends to that.
CXXFLAGS += -std=c++11 -Wall -Wextra -Wno-unused-parameter -Wno-comment -Wfatal-errors $(OPTFLAGS) $(FEATUREFLAGS) -DCURVE_$(CURVE)

CXXFLAGS += -I$(INSTALL_PATH)/include -I$(INSTALL_PATH)/include/libsnark

CXXFLAGS += -fopenmp -DMULTICORE
LDFLAGS += -L$(INSTALL_PATH)/lib
LDLIBS += -lgmpxx -lgmp -lboost_program_options
# OpenSSL and its dependencies (needed explicitly for static builds):
LDLIBS += -lcrypto -ldl -lz -lsnark

EXECUTABLES = \
	main \
	test

EXEC_OBJS =$(patsubst %,%.o,$(EXECUTABLES))

all: $(EXECUTABLES)

# In order to detect changes to #include dependencies. -MMD below generates a .d file for each .o file. Include the .d file.
-include $(patsubst %.o,%.d, $(EXEC_OBJS))


main.o: main.cpp
	$(CXX) -c main.cpp $(CXXFLAGS)

test.o: test.cpp
	$(CXX) -c test.cpp $(CXXFLAGS)

sha256.o: sha256.cpp
	$(CXX) -c sha256.cpp $(CXXFLAGS)

$(EXECUTABLES): %: %.o
	$(CXX) -o $@   $@.o $(SRC_OBJS) $(CXXFLAGS) $(LDFLAGS) $(LDLIBS)

# Clean all, including locally-compiled dependencies
clean: 
	$(RM) *.o $(EXECUTABLES)

.PHONY: clean
