#********************************************************************************
# Makefile for the libsnark library.
#********************************************************************************
#* @author     This file is part of libsnark, developed by SCIPR Lab
#*             and contributors (see AUTHORS).
#* @copyright  MIT license (see LICENSE file)
#*******************************************************************************/

# To override these, use "make OPTFLAGS=..." etc.
CURVE = BN128
OPTFLAGS = -O2 -march=native -mtune=native -g
FEATUREFLAGS = -DUSE_ASM -DMONTGOMERY_OUTPUT -DNO_PROCPS
CXX = g++

INSTALL_PATH = /usr/local
# Initialize this using "CXXFLAGS=... make". The makefile appends to that.
CXXFLAGS += -std=c++11 -Wall -Wextra -Wno-unused-parameter -Wno-comment -Wfatal-errors $(OPTFLAGS) $(FEATUREFLAGS) -DCURVE_$(CURVE)

CXXFLAGS += -I$(INSTALL_PATH)/include

CXXFLAGS += -fopenmp -DMULTICORE
LDFLAGS += -L$(INSTALL_PATH)/lib
LDLIBS += -lgmpxx -lgmp -lboost_program_options
# OpenSSL and its dependencies (needed explicitly for static builds):
LDLIBS += -lcrypto -ldl -lz -lsnark -lff -lprocps

EXECUTABLES = \
	main \
	test

EXEC_OBJS =$(patsubst %,%.o,$(EXECUTABLES))

DEPENDS = \
	zkspv_cp.hpp \
	zkspv_lm.hpp \
	sha256_2_gadget.hpp \
	run_r1cs_zkspv_demo.hpp



all: $(EXECUTABLES)

# In order to detect changes to #include dependencies. -MMD below generates a .d file for each .o file. Include the .d file.
-include $(patsubst %.o,%.d, $(EXEC_OBJS))


main.o: main.cpp
	$(CXX) -c main.cpp $(CXXFLAGS)

test.o: test.cpp $(DEPENDS)
	$(CXX) -c test.cpp $(CXXFLAGS)

sha256.o: sha256.cpp $(DEPENDS)
	$(CXX) -c sha256.cpp $(CXXFLAGS)

$(EXECUTABLES): %: %.o  sha256.o $(DEPENDS)
	$(CXX) -o $@   $@.o sha256.o $(CXXFLAGS) $(LDFLAGS) $(LDLIBS)

# Clean all, including locally-compiled dependencies
clean: 
	$(RM) *.o $(EXECUTABLES)

.PHONY: clean
