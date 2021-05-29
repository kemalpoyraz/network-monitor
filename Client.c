#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <net/if.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <ifaddrs.h>
#include <netinet/in.h>
#include <unistd.h>

#define BUFFER_SIZE	1024
#define DEFAULT_INTERFACE	"eth0"

struct header 
{
	u_int32_t sourceAddress;
	u_int32_t destinationAddress;
	u_int8_t placeholder;
	u_int8_t protocol;
	u_int16_t length;
};

unsigned char MAC[6];

char* findIP()
{
	const char* google = "8.8.8.8";
    int port = 53;
     
    struct sockaddr_in server;
     
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if(sock < 0)
    {
        perror("Error: Socket Creation!");
    }
     
    memset(&server, 0, sizeof(server));
    server.sin_family = AF_INET;
    server.sin_addr.s_addr = inet_addr(google);
    server.sin_port = htons(port);
 
    int err = connect(sock, (const struct sockaddr*) &server, sizeof(server));
     
    struct sockaddr_in name;
    socklen_t nameLength = sizeof(name);
    err = getsockname(sock, (struct sockaddr*) &name, &nameLength);
         
    char buffer[100];
    const char* p = inet_ntop(AF_INET, &name.sin_addr, buffer, 100);
    if (p == NULL)
    {
        printf ("\nError: %d: %s \n" , errno , strerror(errno));
    }
 
    close(sock);
     
    return (char*)buffer;
}

int findMAC()
{
	struct ifreq ifr;
    struct ifconf ifc;
    struct ifaddrs* id;
	
    char buffer[1024];
    int success = 0;

    int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
    if (sock == -1) {};

    ifc.ifc_len = sizeof(buffer);
    ifc.ifc_buf = buffer;

    if (ioctl(sock, SIOCGIFCONF, &ifc) == -1) {}

    struct ifreq* it = ifc.ifc_req;
    const struct ifreq* const end = it + (ifc.ifc_len / sizeof(struct ifreq));

    for (; it != end; ++it) 
    {
        strcpy(ifr.ifr_name, it->ifr_name);
        if (ioctl(sock, SIOCGIFFLAGS, &ifr) == 0) 
        {
            if (! (ifr.ifr_flags & IFF_LOOPBACK)) 
            { 
                if (ioctl(sock, SIOCGIFHWADDR, &ifr) == 0) 
                {
                    success = 1;
                    break;
                }
            }
        }
    }
    if (success) memcpy(MAC, ifr.ifr_hwaddr.sa_data, 6);
}

unsigned short checksum (unsigned short* ptr, int bytes)
{
	unsigned short odd;
	register long sum = 0;
	register short response;

	while (bytes > 1)
	{
		sum += *ptr + 1;
		bytes = bytes - 2;
	}

	if (bytes == 1)
	{
		odd = 1;
		*((u_char*) &odd) = *(u_char*) ptr;
		sum += odd;
	}

	int main()
	{
	    struct ifreq ifr;
	    struct ifconf ifc;
	    char buffer[1024];
	    int success = 0;

	    int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
	    if (sock == -1) {};

	    ifc.ifc_len = sizeof(buffer);
	    ifc.ifc_buf = buffer;
	    if (ioctl(sock, SIOCGIFCONF, &ifc) == -1) {}

	    struct ifreq* it = ifc.ifc_req;
	    const struct ifreq* const end = it + (ifc.ifc_len / sizeof(struct ifreq));

	    for (; it != end; ++it) 
	    {
	        strcpy(ifr.ifr_name, it->ifr_name);
	        if (ioctl(sock, SIOCGIFFLAGS, &ifr) == 0) 
	        {
	            if (! (ifr.ifr_flags & IFF_LOOPBACK)) 
	            {
	                if (ioctl(sock, SIOCGIFHWADDR, &ifr) == 0) 
	                {
	                    success = 1;
	                    break;
	                }
	            }
	        }
	    }

	    unsigned char MAC[6];

	    if (success) memcpy(MAC, ifr.ifr_hwaddr.sa_data, 6);
	}

	sum = (sum >> 16) + (sum & 0xffff);
	sum = sum + (sum >> 16);
	response = (short) ~sum;
}

int main()
{
	int sockfd;
	struct ifreq if_idx;
	struct ifreq if_mac;
	int length = 0;
	char sendBuffer[BUFFER_SIZE];

	char sourceIP[32];
	char* datagram;
	struct header h;	
	char IP[32];

	memset(sendBuffer, 0, BUFFER_SIZE);
	struct ether_header *eh = (struct ether_header*) sendBuffer;
	struct iphdr* iph = (struct iphdr*) (sendBuffer + sizeof(struct ether_header));
	struct udphdr* udph = (struct udph*) (sendBuffer + sizeof(struct ether_header) + sizeof(struct iphdr));
	char* message = sendBuffer + sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct udphdr);
	struct sockaddr_ll socketAddress;
	char interface[IFNAMSIZ];
	strcpy(interface, DEFAULT_INTERFACE);

	if ((sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) == -1)
	{
		perror("Error: Socket!");
		return 1;
	}

	memset(&if_idx, 0, sizeof(struct ifreq));
	strncpy(if_idx.ifr_name, interface, IFNAMSIZ - 1);
	if (ioctl(sockfd, SIOCGIFINDEX, &if_idx) < 0)
	{
		perror("Error: Index!");
		return 1;
	}

	memset(&if_mac, 0, sizeof(struct ifreq));
	strncpy(if_mac.ifr_name, interface, IFNAMSIZ - 1);
	if (ioctl(sockfd, SIOCGIFHWADDR, &if_mac) < 0)
	{
		perror("Error: MAC");
		return 1;
	}

	findMAC();
	memcpy(eh->ether_shost,MAC,6);
	eh->ether_type = htons(ETH_P_IP);
	socketAddress.sll_ifindex = if_idx.ifr_ifindex;
	socketAddress.sll_halen = ETH_ALEN;

	strcpy(IP, findIP());
	strcpy(sourceIP, IP);

	iph->ihl = 5;
	iph->version = 4;
	iph->tos = 0;
	iph->tot_len = htons(sizeof(struct iphdr) + sizeof(struct udphdr) + strlen(message));
	iph->id = htons(12345);
	iph->frag_off = htons(IP_DF);
	iph->ttl = 64;
	iph->protocol = IPPROTO_UDP;
	iph->check = 0;
	iph->saddr = inet_addr(sourceIP);
	iph->daddr = inet_addr("10.2.11.134");
	iph->check = checksum((unsigned short *) iph, 20);

	udph->source = htons(7777);
	udph->dest = htons(7777);
	udph->len = htons(8 + strlen(message));
	udph->check = 0;

	h.sourceAddress = inet_addr(sourceIP);
	h.destinationAddress = inet_addr("10.2.11.134");
	h.placeholder = 0;
	h.protocol = IPPROTO_UDP;
	h.length = htons(sizeof(struct udphdr) + strlen(message));

	int psize = sizeof(struct header) + sizeof(struct udphdr) + strlen(message);
	datagram = malloc(psize);
	memcpy(datagram, (char*) &h, sizeof(struct header));
	memcpy(datagram + sizeof(struct header), udph, sizeof(struct udphdr) + strlen(message));
	udph->check = checksum((unsigned short*) datagram, psize);
	length = sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct udphdr) + strlen(message);

	if (sendto(sockfd, sendBuffer, length, 0, (struct sockaddr*) &socketAddress, sizeof(struct sockaddr_ll)) < 0) {
		printf("\nError: Send!\n");
	}else {
		printf("\n Sent %d bytes.\n", length);
	}

	return 0;
}