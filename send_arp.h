#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <pcap/pcap.h>
#include <net/ethernet.h>
#include <netinet/ether.h>
#include <string.h>
#include <netinet/in.h> // for ntohs() function


#define ERRBUF_SIZE			100
#define PACKET_MAX_BYTES	300
#define PROMISCUOUS_MODE	1
#define NON_PROMISCUOUS		0
#define WAIT_MAX_TIME		-1


int pcd_init(pcap_t **pcd, char **dev);
void getMyIpMac(struct ether_addr myMac, struct in_addr myIp);
void getGWIp(struct in_addr GWIp);
void ARPrequest_reply(struct ether_addr targetMac,	struct in_addr targetIp,
					struct ether_addr senderMac,	struct in_addr senderIp,	pcap_t *pcd,	int option);

void callback(u_char *useless, const struct pcap_pkthdr *pkthdr, const u_char *packet);
int pcapCapture(struct in_addr* Ip);