#include "send_arp.h"

int count;

int pcapCapture(struct in_addr* Ip){
	char 			*device;					// device name
	char 			errorbuffer[ERRBUF_SIZE];	// Error string
	bpf_u_int32		mask = 0;					// mask information
	bpf_u_int32		net = 0;					// IP information
	pcap_t 			*pcd;					// packet descriptor
	struct in_addr	net_addr;				// address of ip
	struct in_addr	mask_addr;				// address of mask
	const u_char *packet;					// packet

	// find the device
	device = pcap_lookupdev(errorbuffer);
	if (device == NULL) {
		printf("No devices: %s\n", errorbuffer);
		return 0;
	}
	else
		printf("device: %s\n", device);

    // convert the information to look good 
	net_addr.s_addr = net;
	 if(inet_ntoa(net_addr) == NULL) {
        printf("Cannot convert >> net_addr");
        return 0;
	}
	printf("NET : %s\n", inet_ntoa(net_addr));
	mask_addr.s_addr = mask;
	printf("MSK : %s\n", inet_ntoa(mask_addr));
	printf("--------------------------------\n");

	// get device information
	if(pcap_lookupnet(device, &net, &mask, errorbuffer) == -1)
		printf("Cannot get information of devce %s: %s\n", device, errorbuffer);

	// open the device
	pcd = pcap_open_live(device, PACKET_MAX_BYTES, PROMISCUOUS_MODE, WAIT_MAX_TIME, errorbuffer);
	if(pcd == NULL){
		printf("Cannot open device %s: %s\n", device, errorbuffer);
		return 0;
	}

	// get the packet
	pcap_loop(pcd, 0, callback, ((u_char *)&Ip->s_addr));
	
	pcap_close(pcd);

	return 1;
}

void callback(u_char *useless, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
	// useless: struct in_addr* Ip
    // get ehternet header 
    struct ether_header *eth;   // ethernet header struct
    struct ether_arp *arph;     // arp header struct
    eth = (struct ether_header *)packet;
    FILE *fp = fopen("targetmac.txt", "a+");

    // get ARP header   
    packet = packet + sizeof(struct ether_header);

    printf("=============== %04d ===============\n", count);
    count++;
    // if arp
    if(ntohs(eth->ether_type) == ETHERTYPE_ARP){
    	arph = (struct ether_arp *) packet;
        
        printf("\nsource: ");
        for(int i = 0; i<4; i++){
        	printf("%d ", arph->arp_spa[i]);
        }	
        printf("\n");

        if(strncmp(arph->arp_spa, useless, 4) == 0){
            printf("Source MAC      : %02X:%02X:%02X:%02X:%02X:%02X\n", eth->ether_shost[0], eth->ether_shost[1], eth->ether_shost[2], eth->ether_shost[3], eth->ether_shost[4], eth->ether_shost[5]);
            fprintf(fp, "%02X:%02X:%02X:%02X:%02X:%02X\n", eth->ether_shost[0], eth->ether_shost[1], eth->ether_shost[2], eth->ether_shost[3], eth->ether_shost[4], eth->ether_shost[5]);
            //printf("Desitnation MAC : %02X:%02X:%02X:%02X:%02X:%02X\n", eth->ether_dhost[0], eth->ether_dhost[1], eth->ether_dhost[2], eth->ether_dhost[3], eth->ether_dhost[4], eth->ether_dhost[5]);
            fclose(fp);
            return;
        }
    }
    printf("\n\n");
    fclose(fp);
}
