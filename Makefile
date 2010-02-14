ifdef DEBUG
	CFLAGS+=-ggdb -DDEBUG -O0 -Wall
endif

CFLAGS+=$(shell pkg-config --cflags openssl)
LDFLAGS+=$(shell pkg-config --libs openssl)

all: clumble

clumble: clumble.o

#version.c:
#	echo "char clumble_ver[] = "\"0.2-`git log -n1 --pretty=format:%H`\""; char * getversion(void) { return HateXMPP_ver; }" > version.c

.PHONY:	clean

clean:
	rm *.o
	rm version.c
	rm clumble

install: hatexmpp
	install clumble /usr/bin

