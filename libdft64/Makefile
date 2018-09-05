#
# NSL DFT lib (libdft)
#
# Columbia University, Department of Computer Science
# Network Security Lab
#
# Vasileios P. Kemerlis (vpk@cs.columbia.edu)
#

# variable definitions
CXXFLAGS	+= -Wall -c -fomit-frame-pointer -std=c++0x -fPIC\
		  -fno-strict-aliasing -fno-stack-protector	\
		  -DBIGARRAY_MULTIPLIER=1 -DUSING_XED		\
		  -DTARGET_IA32E -DHOST_IA32E -DTARGET_LINUX -g 
CXXFLAGS_SO	+= -Wl,--hash-style=sysv -Wl,-Bsymbolic -shared -fPIC\
		   -Wl,--version-script=$(PIN_HOME)/source/include/pin/pintool.ver
LIBS		+= -lpin  -lxed -ldwarf -lelf -ldl -lcrypto -lssl# -liberty
H_INCLUDE	+= -I. -I$(PIN_HOME)/source/include/pin		\
		   -I$(PIN_HOME)/source/include/pin/gen		\
		   -I$(PIN_HOME)/extras/xed2-intel64/include	\
		   -I$(PIN_HOME)/extras/components/include  
L_INCLUDE	+= -L$(PIN_HOME)/extras/xed2-intel64/lib	\
		-L$(PIN_HOME)/intel64/lib -L$(PIN_HOME)/intel64/lib-ext
TOOLS_DIR	= tools
OBJS		= libdft_api.o libdft_core.o osutils.o syscall_desc.o tagmap.o
TOOLS_OBJS	= $(TOOLS_DIR)/libdft-dta.o
TOOLS_SOBJS	= $(TOOLS_OBJS:.o=.so)

# phony targets
.PHONY: all clean tools tools_clean

# default target (build libdft only)
all: $(OBJS)

# libdft_api
libdft_api.o: libdft_api.cpp libdft_api.h branch_pred.h
	$(CXX) $(CXXFLAGS) $(H_INCLUDE) -o $(@) $(@:.o=.cpp)

# libdft_core
libdft_core.o: libdft_core.cpp libdft_core.h branch_pred.h
	$(CXX) $(CXXFLAGS) $(H_INCLUDE) -o $(@) $(@:.o=.cpp)

# osutils
osutils.o: osutils.cpp osutils.H
	$(CXX) $(CXXFLAGS) $(H_INCLUDE) -o $(@) $(@:.o=.cpp)

# syscall_desc
syscall_desc.o: syscall_desc.cpp syscall_desc.h  branch_pred.h
	$(CXX) $(CXXFLAGS) $(H_INCLUDE) -o $(@) $(@:.o=.cpp)

# libcall_desc
#libcall_desc.o: libcall_desc.cpp libcall_desc.h  branch_pred.h
#	$(CXX) $(CXXFLAGS) $(H_INCLUDE) -o $(@) $(@:.o=.cpp)

# heap_desc
#heap_desc.o: heap_desc.cpp heap_desc.h  branch_pred.h
#	$(CXX) $(CXXFLAGS) $(H_INCLUDE) -o $(@) $(@:.o=.cpp)

# libdft_log
#libdft_log.o: libdft_log.cpp libdft_log.h  branch_pred.h
#	$(CXX) $(CXXFLAGS) $(H_INCLUDE) -o $(@) $(@:.o=.cpp)

# libdft_utils
#libdft_utils.o: libdft_utils.cpp libdft_utils.h  branch_pred.h
#	$(CXX) $(CXXFLAGS) $(H_INCLUDE) -o $(@) $(@:.o=.cpp)

# tagmap
tagmap.o: tagmap.cpp tagmap.h branch_pred.h
	$(CXX) $(CXXFLAGS) $(H_INCLUDE) -o $(@) $(@:.o=.cpp)

# clean (libdft)
obj_clean:
	rm -rf $(OBJS)

# tools (nullpin, libdft, libdft-dta)
tools: $(TOOLS_SOBJS)

# libdft-dta
$(TOOLS_DIR)/libdft-dta.so: $(TOOLS_DIR)/libdft-dta.o $(OBJS)
	$(CXX) $(CXXFLAGS_SO) $(L_INCLUDE) -o $(@) $(@:.so=.o)	\
		$(OBJS) $(LIBS)
$(TOOLS_DIR)/libdft-dta.o: $(TOOLS_DIR)/libdft-dta.cpp branch_pred.h
	$(CXX) $(CXXFLAGS) $(H_INCLUDE) -o $(@) $(@:.o=.cpp)

# clean (tools)
clean:
	rm -rf $(OBJS)
	rm -rf $(TOOLS_OBJS) $(TOOLS_SOBJS)
