bin_PROGRAMS = killer
pcap_FOLDER = `pcap-config --cflags`
killer_SOURCES = killer.c monitor.c hacking.c hacking-network.c cappacket.c
killer_CFLAGS = -std=gnu11 -Wall $(GLIB_CFLAGS) $(pcap_FOLDER)
killer_LDADD = $(GLIB_LIBS)
