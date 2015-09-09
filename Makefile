CFLAGS+=-std=gnu11 -Wall

all: dtls-server attack

dtls-server: server-dtls-threaded.c
	gcc $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) -o dtls-server server-dtls-threaded.c -pthread -lwolfssl

attack: attack.c
	gcc $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) -o attack attack.c -lwolfssl -lbsd

clean:
	rm dtls-server attack
