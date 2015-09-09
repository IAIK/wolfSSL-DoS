CFLAGS+=-std=gnu11 -Wall

all: dtls-server attack target

dtls-server: server-dtls.c
	gcc $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) -o dtls-server server-dtls.c -pthread -lwolfssl

attack: attack.c
	gcc $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) -o attack attack.c -lwolfssl -lbsd

target: target.c
	gcc $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) -o target target.c

clean:
	rm dtls-server attack target
