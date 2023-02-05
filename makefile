LDLIBS += -lpcap

all: signal-strength

pcap-test: signal-strength.c

clean:
	rm -f signal-strength *.o
