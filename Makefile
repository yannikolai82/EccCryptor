# Cross-platform Makefile for CEccModule.
#
#   make                       - build BOTH backends (default)
#   make BACKEND=openssl       - OpenSSL backend only
#   make BACKEND=mbedtls       - mbedTLS backend only
#   make STATIC=1              - force static link (Linux: needs libcrypto.a)
#   make clean
#
# On Windows, prefer the .bat wrappers (build.bat / build_openssl.bat /
# build_mbedtls.bat) -- they handle the vendored toolchain quirks.

CXX      ?= g++
CC       ?= gcc
CXXFLAGS ?= -std=c++11 -O2 -Wall -Wno-deprecated-declarations
CFLAGS   ?= -std=c99 -O2 -Wall
BACKEND  ?= both

MBED_DIR ?= third_party/mbedtls
MBED_SRC  = aes asn1parse asn1write bignum cipher cipher_wrap constant_time \
            ecdh ecdsa ecp ecp_curves error gcm hkdf md oid platform        \
            platform_util sha256
MBED_OBJS = $(addprefix build_mbedtls_obj/,$(addsuffix .o,$(MBED_SRC)))

ifeq ($(OS),Windows_NT)
    # ---- Windows / MinGW path ----
    OPENSSL_DIR ?= third_party/openssl
    OPENSSL_CXXFLAGS = -I$(OPENSSL_DIR)/include
    OPENSSL_LDFLAGS  = -static-libgcc -static-libstdc++
    OPENSSL_LDLIBS   = -L$(OPENSSL_DIR)/lib -lcrypto -lws2_32 -lcrypt32
    OPENSSL_TARGET   = ecc_demo_openssl.exe
    OPENSSL_COPYDLL  = cp -f $(OPENSSL_DIR)/bin/libcrypto-3-x64.dll \
                              $(OPENSSL_DIR)/bin/libwinpthread-1.dll .

    MBED_CXXFLAGS    = -I$(MBED_DIR)/include -D_WIN32_WINNT=0x0501
    MBED_LDFLAGS     = -static
    MBED_LDLIBS      = -ladvapi32
    MBED_TARGET      = ecc_demo_mbedtls.exe
else
    # ---- Linux / macOS path ----
    OPENSSL_CXXFLAGS =
    OPENSSL_LDFLAGS  =
    OPENSSL_LDLIBS   = -lcrypto
    OPENSSL_TARGET   = ecc_demo_openssl
    OPENSSL_COPYDLL  = true

    MBED_CXXFLAGS    = -I$(MBED_DIR)/include
    MBED_LDFLAGS     =
    MBED_LDLIBS      =
    MBED_TARGET      = ecc_demo_mbedtls
endif

ifeq ($(STATIC),1)
    OPENSSL_LDFLAGS += -static
endif

# Default target list
ifeq ($(BACKEND),openssl)
    ALL = $(OPENSSL_TARGET)
else ifeq ($(BACKEND),mbedtls)
    ALL = $(MBED_TARGET)
else
    ALL = $(OPENSSL_TARGET) $(MBED_TARGET)
endif

all: $(ALL)

# ---- OpenSSL backend ----
$(OPENSSL_TARGET): CEccModule_openssl.cpp CEccModule.h main.cpp
	$(CXX) $(CXXFLAGS) $(OPENSSL_CXXFLAGS) \
		CEccModule_openssl.cpp main.cpp \
		-o $@ $(OPENSSL_LDFLAGS) $(OPENSSL_LDLIBS)
	@$(OPENSSL_COPYDLL)

# ---- mbedTLS backend ----
$(MBED_TARGET): CEccModule_mbedtls.cpp CEccModule.h main.cpp $(MBED_OBJS)
	$(CXX) $(CXXFLAGS) $(MBED_CXXFLAGS) \
		CEccModule_mbedtls.cpp main.cpp $(MBED_OBJS) \
		-o $@ $(MBED_LDFLAGS) $(MBED_LDLIBS)

build_mbedtls_obj/%.o: $(MBED_DIR)/library/%.c
	@mkdir -p build_mbedtls_obj
	$(CC) $(CFLAGS) $(MBED_CXXFLAGS) -c $< -o $@

clean:
	rm -rf build_mbedtls_obj
	rm -f ecc_demo ecc_demo_openssl ecc_demo_mbedtls \
	      ecc_demo.exe ecc_demo_openssl.exe ecc_demo_mbedtls.exe \
	      libcrypto-3-x64.dll libwinpthread-1.dll *.o build*.log

.PHONY: all clean
