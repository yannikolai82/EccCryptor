# Cross-platform Makefile for CEccModule.
#
#   make             - dynamic link (Linux: system OpenSSL; Windows: vendored)
#   make STATIC=1    - static link against libcrypto.a
#   make clean

CXX      ?= g++
CXXFLAGS ?= -std=c++11 -O2 -Wall -Wno-deprecated-declarations
SRC       = CEccModule.cpp main.cpp
HDR       = CEccModule.h

ifeq ($(OS),Windows_NT)
    OPENSSL_DIR ?= third_party/openssl
    CXXFLAGS   += -I$(OPENSSL_DIR)/include
    LDFLAGS    += -static-libgcc -static-libstdc++
    LDLIBS     += -L$(OPENSSL_DIR)/lib -lcrypto -lws2_32 -lcrypt32
    TARGET      = ecc_demo.exe
    COPYDLL     = cp -f $(OPENSSL_DIR)/bin/libcrypto-3-x64.dll $(OPENSSL_DIR)/bin/libwinpthread-1.dll .
else
    # Linux/macOS: install OpenSSL dev headers via your package manager.
    LDLIBS     += -lcrypto
    TARGET      = ecc_demo
    COPYDLL     = true
endif

ifeq ($(STATIC),1)
    LDFLAGS += -static
endif

all: $(TARGET)

$(TARGET): $(SRC) $(HDR)
	$(CXX) $(CXXFLAGS) $(SRC) -o $(TARGET) $(LDFLAGS) $(LDLIBS)
	@$(COPYDLL)

clean:
	rm -f ecc_demo ecc_demo.exe libcrypto-3-x64.dll *.o build.log

.PHONY: all clean
