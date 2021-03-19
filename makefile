CC=g++
CFLAGS=-c -Wall -g -m64
LDFLAGS=-lgmpxx -lgmp -Wl,-Bdynamic -lcryptopp -lpthread
EXECUTABLE=fully_homomorphic

all : $(EXECUTABLE)

$(EXECUTABLE) : main.o vote_counter.o fully_homomorphic.o utilities.o circuit.o security_settings.o
	$(CC) -o $@ main.o vote_counter.o fully_homomorphic.o utilities.o circuit.o cipher_bit.o security_settings.o $(LDFLAGS)

vote_counter.o : vote_counter.cpp
	$(CC) $(CFLAGS) vote_counter.cpp

main.o : main.cpp
	$(CC) $(CFLAGS) main.cpp

utilities.o : utilities.cpp
	$(CC) $(CFLAGS) utilities.cpp

fully_homomorphic.o : fully_homomorphic.cpp fully_homomorphic.h type_defs.h cipher_bit.o
	$(CC) $(CFLAGS) fully_homomorphic.cpp -lgmp -lcryptopp -lpthreads

cipher_bit.o : cipher_bit.cpp
	$(CC) $(CFLAGS) cipher_bit.cpp

circuit.o : circuit.cpp
	$(CC) $(CFLAGS) circuit.cpp

security_settings.o : security_settings.cpp
	$(CC) $(CFLAGS) security_settings.cpp

clean :
	rm -rf *.o fully_homomorphic
