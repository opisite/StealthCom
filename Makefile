CC=g++

CFLAGS=-Wall -g

LIBS=-lpthread -lpcap -lncursesw -lssl -lcrypto

SRCS=$(wildcard src/*.cpp)

OBJS=$(SRCS:.cpp=.o)

MAIN=StealthCom

.PHONY: depend clean

all:    $(MAIN)
	@echo  Compiling $(MAIN) completed.

$(MAIN): $(OBJS) 
	$(CC) $(CFLAGS) -o $(MAIN) $(OBJS) $(LIBS)

.cpp.o:
	$(CC) $(CFLAGS) -c $<  -o $@

clean:
	rm -f src/*.o *.o *~ $(MAIN)

depend: $(SRCS)
	makedepend $^
