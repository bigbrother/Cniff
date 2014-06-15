/////////////////////////////////////////////////////////
//						       //
//						       //
//						       //
//						       //
//						       //
//						       //
//						       //
//						       //
/////////////////////////////////////////////////////////

#include "includes.h"
#include "headers.h"

void
got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);

int main(int argc, char **argv)
{
	  int dev; /* name of the device to use */
	  char *net; /* dot notation of the network address */
	  char *mask;/* dot notation of the network mask    */
	  int num_dev;   /* return code */
	  struct pcap_pkthdr header;
	  const u_char *packet;           /* The actual packet */
	  char errbuf[PCAP_ERRBUF_SIZE];
	  bpf_u_int32 netp; /* ip          */
	  bpf_u_int32 maskp;/* subnet mask */
	  struct in_addr addr;
	  pcap_if_t *alldevsp,*temp_alldevsp;
	  char sniff_dev[10];
	  int num_packets = 10000;
	  

	   /* ask pcap to find a valid device for use to sniff on */
	   pcap_t *handle;
	   printf("\nCniff v0.1 - http://digitalundernet.com/\n");
	   printf("BUFFER SIZE: %d\n", BUFSIZ);
	   printf("Enter device to use.\n");
	   printf("> ");
	   scanf("%s",&sniff_dev);
	   //1 Tells pcap to put the device in promisc mode, 1000 tells it how long before it times out in milliseconds
	   handle = pcap_open_live(sniff_dev, BUFSIZ, 1, 1000, errbuf); 
	     if (handle == NULL) 
	     {
	     		fprintf(stderr, "FAILURE; unable to open device %s:\n",errbuf);
	     }
	      else
	      {
				pcap_loop(handle, num_packets, got_packet, NULL);
	      }               
		
	   pcap_close(handle); 
	   return 0;
}

void
got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{

	static int count = 1;                   /* packet counter */
	/* declare pointers to packet headers */
	const struct sniff_ethernet *ethernet;  /* The ethernet header [1] */
	const struct sniff_ip *ip;              /* The IP header */
	const struct sniff_tcp *tcp;            /* The TCP header */
	const char *payload;                    /* Packet payload */

	int size_ip;
	int size_tcp;
	int size_payload;

	printf("\n------------\n");
	

	/* define ethernet header */
	ethernet = (struct sniff_ethernet*)(packet);

 /* get ethernet header informatiom*/
 
 fprintf(stdout,"\nSource MAC address: %s"
            ,ether_ntoa(ethernet->ether_shost));
 fprintf(stdout," \nDestination MAC address: %s \n"
            ,ether_ntoa(ethernet->ether_dhost));

	/* define compute ip header offset */
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
			printf("\nProtocol: TCP\t");
			break;
		case IPPROTO_UDP:
			printf("   \nProtocol: UDP\n\t");
			return;
		case IPPROTO_ICMP:
			printf("   \nProtocol: ICMP\n\t");
			return;
		case IPPROTO_IP:
			printf("   \nProtocol: IP");
			return;
		default:
			printf("   \nProtocol: unknown\n");
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
		return;
	}

	printf("   Source port: %d\t", ntohs(tcp->th_sport));
	printf("   Destination port: %d\t", ntohs(tcp->th_dport));
    printf("   TCP flags: 0x%x\n",(tcp->th_flags));  

	/* define/compute tcp payload (segment) offset */
	payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_tcp);

	/* compute tcp payload (segment) size */
	size_payload = ntohs(ip->ip_len) - (size_ip + size_tcp);

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

void
print_payload(const u_char *payload, int len)
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

/*
 * print data in rows of 16 bytes: offset   hex   ascii
 *
 * 00000   47 45 54 20 2f 20 48 54  54 50 2f 31 2e 31 0d 0a   GET / HTTP/1.1..
 */
void
print_hex_ascii_line(const u_char *payload, int len, int offset)
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
} //EOF