CXX=g++
FLAGS=-Wall -pedantic
SRC=dns.cpp
HEADERS=dns.hpp
TARGET=dns

.PHONY: test clean

all: $(TARGET)

$(TARGET): $(HEADERS) $(SRC)
	$(CXX) $(FLAGS) -o $@ $^

test: test.cpp
	$(CXX) $(FLAGS) -o $@ $^
	./test

clean:
	rm -f test dns
