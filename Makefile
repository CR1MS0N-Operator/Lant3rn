CC = gcc
CFLAGS = -Wall -Wextra -pedantic -O2 -Isrc -Iinclude -I/usr/include
LDFLAGS = -lldap -llber -ljson-c

OBJS = src/main.o src/config.o src/ldap.o src/ldap_insights.o src/export.o src/error_handler.o src/mock.o

all: aclguard

aclguard: $(OBJS)
	$(CC) -o $@ $(OBJS) $(LDFLAGS)

clean:
	rm -f aclguard test $(OBJS)

test: aclguard
	tests/smoke_test.sh
	tests/ldap_smoke_test.sh
