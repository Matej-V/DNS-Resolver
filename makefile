CXX=g++
FLAGS=-Wall -pedantic -std=c++11 -lm -pthread
SRC=dns.cpp
HEADERS=dns.hpp
TARGET=dns

.PHONY: test clean

all: $(TARGET)

$(TARGET): $(HEADERS) $(SRC)
	$(CXX) $(FLAGS) -o $@ $^

test: dns
	python3 test.py

clean:
	rm -f test dns
