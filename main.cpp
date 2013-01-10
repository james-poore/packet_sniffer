	//
	//  main.cpp
	//  Packet Sniffer v2.0
	//
	//  Created by James Poore on 10/29/11.
	//  Copyright (c) 2011 James Poore. All rights reserved.
	//




using namespace std;

#define _BSD_SOURCE 1


#define SIZE_OF_ARRAY 150
#define SIZE_OF_LITTLE_ARRAY 2

#include <iostream>
#include <pcap.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <regex.h>

char searchTerm [SIZE_OF_ARRAY] = "";

/*Packet Header Structures*/
/*----------------------------------------------------------------------------------------------------------------------------*/
/* Ethernet addresses are 6 bytes */
#define ETHER_ADDR_LEN	6

/* Ethernet header */
struct sniff_ethernet {
	u_char ether_dhost[ETHER_ADDR_LEN]; /* Destination host address */
	u_char ether_shost[ETHER_ADDR_LEN]; /* Source host address */
	u_short ether_type; /* IP? ARP? RARP? etc */
};

/* IP header */
struct sniff_ip {
	u_char ip_vhl;		/* version << 4 | header length >> 2 */
	u_char ip_tos;		/* type of service */
	u_short ip_len;		/* total length */
	u_short ip_id;		/* identification */
	u_short ip_off;		/* fragment offset field */
#define IP_RF 0x8000		/* reserved fragment flag */
#define IP_DF 0x4000		/* dont fragment flag */
#define IP_MF 0x2000		/* more fragments flag */
#define IP_OFFMASK 0x1fff	/* mask for fragmenting bits */
	u_char ip_ttl;		/* time to live */
	u_char ip_p;		/* protocol */
	u_short ip_sum;		/* checksum */
	struct in_addr ip_src,ip_dst; /* source and dest address */
};
#define IP_HL(ip)		(((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)		(((ip)->ip_vhl) >> 4)

/* TCP header */
struct sniff_tcp {
	u_short th_sport;	/* source port */
	u_short th_dport;	/* destination port */
//	u_short th_seq;		/* sequence number */
//	u_short th_ack;		/* acknowledgement number */
	
	u_char th_offx2;	/* data offset, rsvd */
#define TH_OFF(th)	(((th)->th_offx2 & 0xf0) >> 4)
	u_char th_flags;
#define TH_FIN 0x01
#define TH_SYN 0x02
#define TH_RST 0x04
#define TH_PUSH 0x08
#define TH_ACK 0x10
#define TH_URG 0x20
#define TH_ECE 0x40
#define TH_CWR 0x80
#define TH_FLAGS (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
	u_short th_win;		/* window */
	u_short th_sum;		/* checksum */
	u_short th_urp;		/* urgent pointer */
};

#define SIZE_ETHERNET 14

const struct sniff_ethernet *ethernet; /* The ethernet header */
const struct sniff_ip *ip; /* The IP header */
const struct sniff_tcp *tcp; /* The TCP header */
const char *payload; /* Packet payload */

u_int size_ip;
//u_int size_tcp;
/*----------------------------------------------------------------------------------------------------------------------------*/


/* Functions */
/*----------------------------------------------------------------------------------------------------------------------------*/
bool isRootUser(void);
void getPacket(u_char *count, const struct pcap_pkthdr* pkthdr, const u_char *packet);
void useFilter(char* loadFilter, char* filter_exp, pcap_t* sniffSession, struct bpf_program portFilter, bpf_u_int32 net);
void getSearchTerm();
void print_hex_ascii_line(const u_char *payload, int len, int offset);
void print_payload(const u_char *payload, int len);

/*----------------------------------------------------------------------------------------------------------------------------*/

/* MAIN */
int main (int argc, char * argv[])
{
    int count = 0, packetsToCapture = 0, option;				//Counter and variable for storing the number of packets to be captured
	const int bytesToCapture = 65536;					//Should be large enough to capture an entire packet of average size
    pcap_t *sniffSession = NULL;						//The sniff session
	pcap_if_t *allDevices, *d;							//The list of available network interfaces/devices
	pcap_dumper_t *dumper = NULL;						//The dumper
	u_int inum, i = 0;									//More counters
	struct bpf_program portFilter;						//The filter
	char filter_exp [SIZE_OF_ARRAY];					//The filter expression currently hardcoded until input works
	char loadFile [SIZE_OF_LITTLE_ARRAY];				//Variable to decide whether to use a file or not
	char loadFilter [SIZE_OF_LITTLE_ARRAY];				//Variable to decide whether to use a filter or not
	char loadDump [SIZE_OF_LITTLE_ARRAY];				//Variable to decide whether to dump to a file or not
	char filename [SIZE_OF_ARRAY];						//Name of the file to be parsed for packets
	char dumpFile [SIZE_OF_ARRAY];						//Name of the file to dump the output to
	char errbuff[PCAP_ERRBUF_SIZE], *device = NULL;		//Error buffer and device name
	memset(errbuff, 0, PCAP_ERRBUF_SIZE);
	bpf_u_int32 net;
	bpf_u_int32 mask;
	string::iterator iterator;
	
	
	/*Test if the user is root or not.  If user is root run the program, else end the program.*/
	if (isRootUser()) {
		printf("\nPacket Sniffer\n\n\n\n");
	}
	
	else {
		printf("\nYou must be logged in as root!\n\n");
		exit(EXIT_FAILURE);
	}
	
	/* New Interface */
	/*----------------------------------------------------------------------------------------------------------------------------*/
	printf("Please choose an option from below.\n\n");
	printf("-------------------------------------\n");
	printf("|   1. Load a file                  |\n");
	printf("|   2. Live capture                 |\n");
	printf("|   3. Exit Packet Sniffer          |\n");
	printf("-------------------------------------\n\n");
	
	scanf("%2d", &option);
//	system("clear");
	
	switch (option) {
		case 1:
			printf("Please enter the file name. [path/filename] ");
			
			while (strcmp(fgets(filename, SIZE_OF_ARRAY, stdin), "\n") == 0 ) 
			{
					//Consume the extra \n characters
			}
			
			/*Remove the trailing \n character*/
			if (filename[strlen(filename) - 1] == '\n') {
				filename[strlen(filename) - 1] = '\0';
			}
			
			sniffSession = pcap_open_offline(filename, errbuff);
			
			if (sniffSession == NULL) {
				fprintf(stderr,"Couldn't open pcap file:  \n%s\n", /*filename,*/ errbuff);
				exit(EXIT_FAILURE);
			}
			
			useFilter(loadFilter, filter_exp, sniffSession, portFilter, net);
//			system("clear");
			
			getSearchTerm();
			
			break;
			
		case 2:
			if (pcap_findalldevs(&allDevices, errbuff) == -1) {
				fprintf(stderr, "\nNo devices could be found. %s\n", errbuff);
				exit(EXIT_FAILURE);
			}
			
			/*Print the list of network interfaces out*/
			printf("\nPlease choose an interface from below\n");
			printf("\n-------------------------------------\n");
			
			for (d = allDevices; d; d = d -> next) {
				printf("|   %d. %s\t\t\t    |\n", ++(i), d -> name);
			}
			
			printf("-------------------------------------\n");
			
			if (i == 0) {
				printf("\nNo interfaces found!\n");
				exit(EXIT_FAILURE);
			}
			
			/*User selects an interface to use*/
			scanf("%2d", &inum);
			
			if (inum < 1 || inum > i) {
				printf("\nThat is not a valid interface selection.\n");
				pcap_freealldevs(allDevices);
				exit(EXIT_FAILURE);
			}
			
			for (d = allDevices, i = 0; i < inum - 1; d = d -> next, i++);
			device = d -> name;
			
			if (device == NULL) {
				fprintf(stderr, "\nCouldn't find the specified device: %s\n\n", device);
				exit(EXIT_FAILURE);
			}
			
			/*Look up the subnet mask of the selected interface*/
			if (pcap_lookupnet(device, &net, &mask, errbuff) == -1) {
				fprintf(stderr, "\nCan't get the netmask for the specified device: %s\n\n", device);
				net = 0;
				mask = 0;
					//exit(EXIT_FAILURE);
			}
			
			//system("clear");
			
			printf("\n-------------------");
			printf("\nOpening device: %s", device);
			printf("\n-------------------\n");
			
			sleep(2);
			//system("clear");
			
			/*User selects how much to capture*/
			printf("\nHow many packets would you like to capture? [-1 will capture until the program is terminated] ");
			scanf("%10d", &packetsToCapture);
			
			//system("clear");
			
			/*Open the interface in promiscuous mode and prepare for sniffing*/
			sniffSession = pcap_open_live(device, bytesToCapture, 1, 512, errbuff);
			
			if (sniffSession == NULL) {
				fprintf(stderr, "\nCouldn't open the specified device: %s\n", errbuff);
				exit(EXIT_FAILURE);
			}
			
			useFilter(loadFilter, filter_exp, sniffSession, portFilter, net);
			
			printf("\nWould you like to save the output to a file? [y/n] ");
			
			while (strcmp(fgets(loadDump, SIZE_OF_LITTLE_ARRAY, stdin), "\n") == 0 ) 
			{
					//Consume the extra \n characters
			}
			
			/*Remove the trailing \n character*/
			if (loadDump[strlen(loadDump) - 1] == '\n') {
				loadDump[strlen(loadDump) - 1] = '\0';
			}
			
			//system("clear");
			
			/*User inputs name of dump file and it is created for the dumping session.*/
			if (strcmp(loadDump, "Y") == 0 || strcmp(loadDump, "y") == 0) {
				printf("\nPlease input the name of the file you would like to output to. [filename] ");
				while (strcmp(fgets(dumpFile, SIZE_OF_ARRAY, stdin), "\n") == 0 ) 
				{
						//Consume the extra \n characters
				}
				
				/*Remove the trailing \n character*/
				if (dumpFile[strlen(dumpFile) - 1] == '\n') {
					dumpFile[strlen(dumpFile) - 1] = '\0';
				}
				
				dumper = pcap_dump_open(sniffSession, dumpFile);
			}
			
			
			else {
				getSearchTerm();
			}
			
			//system("clear");
			
			break;
			
		case 3:
			exit(EXIT_SUCCESS);
			
			break;
			
		default:
			exit(EXIT_SUCCESS);
			
			break;
			
	}
	
	/*If dumping to a file is selected then do so, otherwise output to the console.*/
	if (dumper != NULL) {
		pcap_loop(sniffSession, packetsToCapture, &pcap_dump, (u_char *)dumper);
	}
	
	else {
		/*Begin the loop that will perform the capturing until the desired amount of packets is obtained*/
		pcap_loop(sniffSession, packetsToCapture, getPacket, (u_char *)&count);
		printf("\n\n\n\n");
	}

	/* End of New Interface */
	/*----------------------------------------------------------------------------------------------------------------------------*/
	
	return EXIT_SUCCESS;
}
/* END OF MAIN */
/*----------------------------------------------------------------------------------------------------------------------------*/





/*Get the ID of the user.  Needs to be 0.  User needs to be root to initiate a packet capturing session.*/
bool isRootUser(void)
{
	return getuid() == 0;
}

void print_hex_ascii_line(const u_char *payload, int len, int offset)
{
	
	int i;
	int gap;
	const u_char *ch;
	
	/* offset */
	printf("%05d   ", offset);
	
	/* hex */
	ch = payload;
	for(i = 0; i < len; i++) {
		printf("%02x ", *ch);
		ch++;
		/* print extra space after 8th byte for visual aid */
		if (i == 7)
			printf(" ");
	}
	/* print space to handle line less than 8 bytes */
	if (len < 8)
		printf(" ");
	
	/* fill hex gap with spaces if not full line */
	if (len < 16) {
		gap = 16 - len;
		for (i = 0; i < gap; i++) {
			printf("   ");
		}
	}
	printf("   ");
	
	/* ascii (if printable) */
	ch = payload;
	for(i = 0; i < len; i++) {
		if (isprint(*ch))
			printf("%c", *ch);
		else
			printf(".");
		ch++;
	}
	
	printf("\n");
	
	return;
}

void print_payload(const u_char *payload, int len)
{
	
	int len_rem = len;
	int line_width = 16;			/* number of bytes per line */
	int line_len;
	int offset = 0;					/* zero-based offset counter */
	const u_char *ch = payload;

	if (len <= 0)
		return;
	
	/* data fits on one line */
	if (len <= line_width) {
		print_hex_ascii_line(ch, len, offset);
		return;
	}

	/* data spans multiple lines */
	for ( ;; ) {
		/* compute current line length */
		line_len = line_width % len_rem;
		/* print line */
		print_hex_ascii_line(ch, line_len, offset);
		/* compute total remaining */
		len_rem = len_rem - line_len;
		/* shift pointer to remaining bytes to print */
		ch = ch + line_len;
		/* add offset */
		offset = offset + line_width;
		/* check if we have line width chars or less */
		if (len_rem <= line_width) {
			/* print last line and get out */
			print_hex_ascii_line(ch, len_rem, offset);
			break;
		}
	}
	
	return;
}

void processPacket(const u_char *packet){
	static int count1 = 1;                   /* packet counter */
	
	/* declare pointers to packet headers */
	const struct sniff_ethernet *ethernet;  /* The ethernet header [1] */
	const struct sniff_ip *ip;              /* The IP header */
	const struct sniff_tcp *tcp;            /* The TCP header */
	u_char *payload;                    /* Packet payload */
	
	int size_ip;
	int size_tcp;
	int size_payload;
	
	printf("\nPacket number %d:\n", count1);
	count1++;
	
	/* define ethernet header */
	ethernet = (struct sniff_ethernet*)(packet);
	
	/* define/compute ip header offset */
	ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
	size_ip = IP_HL(ip)*4;
	if (size_ip < 20) {
		printf("   * Invalid IP header length: %u bytes\n", size_ip);
		return;
	}
	
	/* print source and destination IP addresses */
	printf("       From: %s\n", inet_ntoa(ip->ip_src));
	printf("         To: %s\n", inet_ntoa(ip->ip_dst));

	/* determine protocol */	
	switch(ip->ip_p) {
		case IPPROTO_TCP:
			printf("   Protocol: TCP\n");
			break;
		case IPPROTO_UDP:
			printf("   Protocol: UDP\n");
			return;
		case IPPROTO_ICMP:
			printf("   Protocol: ICMP\n");
			return;
		case IPPROTO_IP:
			printf("   Protocol: IP\n");
			return;
		default:
			printf("   Protocol: unknown\n");
			return;
	}
	
	/*
	 *  OK, this packet is TCP.
	 */
	
	/* define/compute tcp header offset */
	tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
	size_tcp = TH_OFF(tcp)*4;
	if (size_tcp < 20) {
		printf("   * Invalid TCP header length: %u bytes\n", size_tcp);
//		return;
	}
	
	printf("   Src port: %d\n", ntohs(tcp->th_sport));
	printf("   Dst port: %d\n", ntohs(tcp->th_dport));
	
	/* define/compute tcp payload (segment) offset */
	payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_tcp);
	
	/* compute tcp payload (segment) size */
	size_payload = ntohs(ip->ip_len) - (size_ip + size_tcp);
	
	/* fix for weird non-printing payload issue
	 * why this works is beyond us - Jean Gourd and James Poore
	*/
	if (size_payload <= 0)
	{
		size_payload += 64;
		payload -= 64;
	}

	/*
	 * Print payload data; it might be binary, so don't just
	 * treat it as a string.
	 */
	if (size_payload > 0) {
		printf("   Payload (%d bytes):\n", size_payload);
		print_payload(payload, size_payload);
	}
	
	return;
}

/*Print out information about each packet as it is captured.  This is the function to be run by the //pcap_loop
 callback function during the sniffing session.*/
void getPacket(u_char *count, const struct pcap_pkthdr* pkthdr, const u_char *packet)
{
    int i = 0, *counter = (int *) count, *counter2 = (int *) count, err;
	char errbuff[SIZE_OF_ARRAY], newPacket [pkthdr->len+1];
	regex_t regex;
	
	/*Eliminate the \0 character and replace it with \1. This is done because the regexec function only searches up
	 to the \0 character, which in this instance may occur before the end of the packet.  So by replacing it, it is
	 guaranteed that the regexec function will search through the entire packet.*/
	for (i = 0; i < pkthdr -> len; i++) {
		if ((packet[i]) != '\0')
			newPacket[i] = packet[i];
		else
			newPacket[i] = '\1';
	}
	newPacket[i] = 0;
	
	(*counter) = (int) ++(*counter);
	
	/*If there is a search term then create a regular expression to use to filter out packets containing the
	 search term.*/
	if (strcmp(searchTerm, "") != 0) {
		
		/*Compile the regular expression using the given search term.*/
		if ((err = regcomp(&regex, searchTerm, REG_EXTENDED)) != 0) {
			regerror(err, &regex, errbuff, SIZE_OF_ARRAY);
			printf("Error analyzing the search term '%s'\n\n: %s. \n", searchTerm, errbuff);
			exit(EXIT_FAILURE);
		}
		
		/*Search through the packets as they come in from the interface and only print out the
		 ones that match the regular expression.*/
		if ((err = regexec(&regex, (char *)newPacket, 0, NULL, 0)) == 0) {
			processPacket(packet);
		}
		
		else {
			regerror(err, &regex, errbuff, SIZE_OF_ARRAY);
				//printf("%s: %s \n",searchTerm, errbuff);
		}
		
	}
	
	else {
		processPacket(packet);
	}
	
    return;
}

void useFilter(char* loadFilter, char* filter_exp, pcap_t* sniffSession, struct bpf_program portFilter, bpf_u_int32 net)
{
	printf("\nWould you like to use a filter? [y/n] ");
	while (strcmp(fgets(loadFilter, SIZE_OF_LITTLE_ARRAY, stdin), "\n") == 0 ) 
	{
			//Consume the extra \n characters
	}
	
	/*Remove the trailing \n character*/
	if (loadFilter[strlen(loadFilter) - 1] == '\n') {
		loadFilter[strlen(loadFilter) - 1] = '\0';
	}
	
//	system("clear");
	
	if (strcmp(loadFilter, "Y") == 0 || strcmp(loadFilter, "y") == 0) {
		printf("\nPlease specify the filter expression. [Options: port #] ");
		
		while (strcmp(fgets(filter_exp, SIZE_OF_ARRAY, stdin), "\n") == 0 ) 
		{
				//Consume the extra \n characters
		}
		
		/*Remove the trailing \n character*/
		if (filter_exp[strlen(filter_exp) - 1] == '\n') {
			filter_exp[strlen(filter_exp) - 1] = '\0';
		}
		
		if (pcap_compile(sniffSession, &portFilter, filter_exp, 0, net) == -1) {
			fprintf(stderr, "\nCouldn't parse the filter: %s. \t%s\n", filter_exp, pcap_geterr(sniffSession));
			exit(EXIT_FAILURE);
		}
		
		if (pcap_setfilter(sniffSession, &portFilter) == -1) {
			fprintf(stderr, "\nCouldn't install the filter %s: %s\n", filter_exp, pcap_geterr(sniffSession));
			exit(EXIT_FAILURE);
		}
	}
	
//	system("clear");
}

void getSearchTerm()
{	
	char search[2];
	
	printf("\nWould you like to narrow the results with a search term? [y/n] ");
	
	while (strcmp(fgets(search, SIZE_OF_LITTLE_ARRAY, stdin), "\n") == 0 ) 
	{
		/*Consume the extra \n characters*/
	}
	
	/*Remove the trailing \n character*/
	if (search[strlen(search) - 1] == '\n') {
		search[strlen(search) - 1] = '\0';
	}
	
//	system("clear");
	
	if (strcmp(search, "Y") == 0 || strcmp(search, "y") == 0) {
		printf("\nPlease enter the search term:\t");
		
		while (strcmp(fgets(searchTerm, SIZE_OF_ARRAY, stdin), "\n") == 0 ) 
		{
				//Consume the extra \n characters
		}
		
		/*Remove the trailing \n character*/
		if (searchTerm[strlen(searchTerm) - 1] == '\n') {
			searchTerm[strlen(searchTerm) - 1] = '\0';
		}
	}
}





