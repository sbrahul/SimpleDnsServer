TARGET=SimpleDnsServer
PREFIX ?= /usr/local/bin
CXX ?= g++
COMPFLAGS := -Wall -std=c++11 -O2

.PHONY: clean all install

all: $(TARGET)
$(TARGET): $(TARGET).cpp
	$(CXX) $(CXXFLAGS) $(COMPFLAGS) $< -o $@

install: $(TARGET)
	install -d $(PREFIX)
	install -m 555 $(TARGET) $(PREFIX)/$(TARGET)

clean:
	rm -f $(TARGET)
