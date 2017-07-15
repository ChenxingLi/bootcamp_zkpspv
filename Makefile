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
FEATUREFLAGS = -DUSE_ASM -DMONTGOMERY_OUTPUT


INSTALL_PATH = /usr/local
# Initialize this using "CXXFLAGS=... make". The makefile appends to that.
CXXFLAGS += -std=c++11 -Wall -Wextra -Wno-unused-parameter -Wno-comment -Wfatal-errors $(OPTFLAGS) $(FEATUREFLAGS) -DCURVE_$(CURVE)

CXXFLAGS += -I$(INSTALL_PATH)/include -I$(INSTALL_PATH)/include/libsnark
LDFLAGS += -L$(INSTALL_PATH)/lib
LDLIBS += -lgmpxx -lgmp -lboost_program_options
# OpenSSL and its dependencies (needed explicitly for static builds):
LDLIBS += -lcrypto -ldl -lz -lsnark

EXECUTABLES = \
	profile_r1cs_sp_ppzkpcd 

LIBSNARK_A = libsnark.a

# For documentation of the following options, see README.md .

# ifeq ($(NO_PROCPS),1)
# 	CXXFLAGS += -DNO_PROCPS
# else
# 	LDLIBS += -lprocps
# endif

# ifeq ($(LOWMEM),1)
# 	CXXFLAGS += -DLOWMEM
# endif

# ifeq ($(PROFILE_OP_COUNTS),1)
# 	STATIC = 1
# 	CXXFLAGS += -DPROFILE_OP_COUNTS
# endif

# ifeq ($(STATIC),1)
# 	CXXFLAGS += -static -DSTATIC
# else
# 	CXXFLAGS += -fPIC
# endif

# ifeq ($(MULTICORE),1)
# 	CXXFLAGS += -DMULTICORE -fopenmp
# endif

# ifeq ($(CPPDEBUG),1)
#         CXXFLAGS += -D_GLIBCXX_DEBUG -D_GLIBCXX_DEBUG_PEDANTIC
#         DEBUG = 1
# endif

# ifeq ($(DEBUG),1)
#         CXXFLAGS += -DDEBUG -ggdb3
# endif

# ifeq ($(PERFORMANCE),1)
#         OPTFLAGS = -O3 -march=native -mtune=native
#         CXXFLAGS += -DNDEBUG
#         # Enable link-time optimization:
#         CXXFLAGS += -flto -fuse-linker-plugin
#         LDFLAGS += -flto
# endif

EXEC_OBJS =$(patsubst %,%.o,$(EXECUTABLES) $(EXECUTABLES_WITH_GTEST) $(EXECUTABLES_WITH_SUPERCOP))

all: $(EXECUTABLES)

# In order to detect changes to #include dependencies. -MMD below generates a .d file for each .o file. Include the .d file.
-include $(patsubst %.o,%.d, $(EXEC_OBJS) )

$(EXEC_OBJS): %.o: %.cpp
	$(CXX) -o $@   $< -c -MMD $(CXXFLAGS)

$(EXECUTABLES): %: %.o
	$(CXX) -o $@   $@.o $(CXXFLAGS) $(LDFLAGS) $(LDLIBS)

# Clean all, including locally-compiled dependencies
clean: 
	$(RM) $(EXEC_OBJS) $(EXECUTABLES)

.PHONY: clean
