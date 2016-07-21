send_arp: send_arp.o pcap.o
	gcc -o send_arp send_arp.o pcap.o -lpcap
        
send_arp.o: send_arp.h send_arp.c
	gcc -o send_arp.o -c send_arp.c

pcap.o: send_arp.h pcap.c
	gcc -o pcap.o -c pcap.c

clean:
	rm -f *.o send_arp
