#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <net/if.h>
#include <netinet/ether.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
 
#define ETHER_TYPE    0x0800
#define DEFAULT_INTERFACE    "eth0"
#define BUFFER_SIZE    1024

typedef struct MACList
{
	char IP[20];
	uint8_t MAC[6];
	struct MACList* next;
} MACList;

MACList* head = NULL;
MACList* end = NULL;
MACList* cur = NULL;
MACList* temp = NULL;

char senderAddress[INET6_ADDRSTRLEN];

int compareUint8_t(uint8_t* linkedList, uint8_t* client, int size)
{
	int lenght = 0;
	while(lenght < size)
	{
		if(linkedList[lenght] != client[lenght])
		{
			return 0;
		}
		
		lenght++;
	}
	return 1;
}

int searchMAC(uint8_t* MAC)
{
    temp = head;
    int i = 0;
    int k = 0;
    int exit = 0;

    while(temp != NULL)
    {
	k = compareUint8_t(temp->MAC, MAC, 6);
        if(k)
        {	
           return 1;
        }
        temp = temp->next;
   }
   return 0;
}

MACList* createNewMAC(uint8_t* MAC, char* IP)
{
    int i = 0;
    MACList* newMAC = NULL;
    newMAC = (MACList*)malloc(sizeof(MACList));
    strcpy(newMAC->IP, IP);

    while(i < 6)
    {
    	newMAC->MAC[i] = MAC[i];
    	i++;
    }
    newMAC->next = NULL;

    i=0;
    while(i < 6)
    {
		printf("%02X ", newMAC->MAC[i]);
		i++;
    }
    return newMAC;
}

void addMAC(uint8_t* MAC, char *IP)
{
    if (head == NULL)
    {
        head = createNewMAC(MAC, IP);
        return;
    }

    temp = head;
    int i = 0;
    while (temp != NULL)
    {
        end = temp;
        printf("\n%s\n%d\n", temp->IP, i);
        i++;
        temp = temp->next;
    }
    end->next = createNewMAC(MAC, IP);    
}

void controlAccess(int option, char* IP)
{
	int i;
	char str[100];
	printf("\n%s\n", IP);

	if(option == 1)
	{
		sprintf(str,"iptables -I FORWARD -s %s -j ACCEPT",IP);
		system(str);
	}
	else if(option == 0)
	{
		sprintf(str,"iptables -D FORWARD -s %s -j ACCEPT",IP);
		for (i = 0; i < 10; i++);
			system(str);
	}
}

int main (int argc, char* argv[])
{
	int sockfd;
	int ret;
	int socketopt;
	struct ifreq ifopts;
	struct sockaddr_storage their_addr;
	uint8_t MAC[6];
	char interface[IFNAMSIZ];
	uint8_t buffer[BUFFER_SIZE];

	MACList *head = malloc(sizeof(MACList));
    MACList *end = malloc(sizeof(MACList));
    MACList *cur = malloc(sizeof(MACList));
    MACList *newMAC = malloc(sizeof(MACList));
    MACList *temp = malloc(sizeof(MACList));

    ssize_t numBytes;
    

	system("iptables -F");

	int i = 0;
	for (i = 0; i < 5; i++)
	{
		system("iptables -I FORWARD --in-interface eth0 -j REJECT");
	}

	struct ether_header* eh = (struct ether_header*) buffer;
    struct iphdr* iph = (struct iphdr*) (buffer + sizeof(struct ether_header));
    struct udphdr* udph = (struct udphdr*) (buffer + sizeof(struct iphdr) + sizeof(struct ether_header));

    if ((sockfd = socket(PF_PACKET, SOCK_RAW, htons(ETHER_TYPE))) == -1) 
    {
        perror("Error: Server Socket!");
        return -1;
    }

    strcpy(interface, DEFAULT_INTERFACE);
    strncpy(ifopts.ifr_name, interface, IFNAMSIZ - 1);
    ioctl(sockfd, SIOCGIFFLAGS, &ifopts);
    ifopts.ifr_flags |= IFF_PROMISC;
    ioctl(sockfd, SIOCSIFFLAGS, &ifopts);

    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &socketopt, sizeof socketopt) == -1)
    {
        perror("Error: Socket Opt!");
        exit(EXIT_FAILURE);
    }

    if (setsockopt(sockfd, SOL_SOCKET, SO_BINDTODEVICE, interface, IFNAMSIZ - 1) == -1)
    {
        perror("Error: Binding!");
        exit(EXIT_FAILURE);
    }

    head = NULL;
    while (1)
    {
    	numBytes = recvfrom(sockfd, buffer, BUFFER_SIZE, 0, NULL, NULL);

    	((struct sockaddr_in*) &their_addr)->sin_addr.s_addr = iph->saddr;
            inet_ntop(AF_INET, &((struct sockaddr_in*) &their_addr)->sin_addr, senderAddress, sizeof senderAddress);

        printf("\nSource IP: %s\n", senderAddress);
        ret = ntohs(udph->len) - sizeof(struct udphdr);
        printf("\nPayload length: %d\n", ret);

        int j = 0;
        for (i = 0; i < numBytes; i++)
        {
        	if (i >= 6 && i < 12)
        	{
        		MAC[j] = buffer[i];
        		printf("%02X ", MAC[j]);
        		j++;
        	}
        }

         if (argv[1] == "1")
         {
         	addMAC(MAC, senderAddress);
			controlAccess(1, senderAddress);
         }
         else
         {
         	controlAccess(0, senderAddress);
         }

         printf("\n\n\n");
    }
    return 0;
}