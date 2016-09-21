nclude <stdio.h>
#include <pcap.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <stdlib.h>
#include <libnet.h>
#include <stdint.h>
#define PCAP_TIMEOUT 200
#define PCAP_SNAPSHOT 1024

static int count;

void packet_view(unsigned char* user, const struct pcap_pkthdr* Pcap, const unsigned char* p);

int main(int argc, char *argv[])
{
	char *dev;
	struct in_addr Net, Mask;
	char err[PCAP_ERRBUF_SIZE];
	bpf_u_int32 net, mask;
	pcap_t *pd;

	if((dev=pcap_lookupdev(err))==NULL)
	{
		printf("\nerror:pcap_lookupdev()\n");
		perror(err);
		exit(1);
	}
	else
		printf("DEV: %s\n",dev);

	if(pcap_lookupnet(dev,&net,&mask,err)<0){
	printf("\nPcap_lookupnet() Error\n");
	perror(err);
	exit(1);
	}

	Net.s_addr=net;
	Mask.s_addr=mask;


	printf("Net Address: %s\n",inet_ntoa(Net));
	printf("Netmask : %s\n",inet_ntoa(Mask));

	if((pd=pcap_open_live(dev,PCAP_SNAPSHOT,1,PCAP_TIMEOUT,err))==NULL)
	{
		printf("\nPcap Open Error\n");
		perror(err);
		exit(1);
	}

	if(pcap_loop(pd,0,packet_view,0)<0)
	{
		printf("\nPcap Loop Error)\n");
		printf("%s\n",pcap_geterr((pcap_t *)dev));
		exit(1);
	}

	pcap_close(pd);
	return 1;
}

void packet_view(unsigned char *user, const struct pcap_pkthdr *Pcap, const unsigned char *p)
{
	int len;
	int i=0,j=0;
	const unsigned char *packet=p;
	struct libnet_ethernet_hdr *Eth;
	struct libnet_ipv4_hdr *Ip;
	struct libnet_tcp_hdr *Tcp;
	struct libnet_udp_hdr *Udp;
	unsigned short ether_type;
	Eth=(struct libnet_ethernet_hdr*)(packet);
	len=0;

	printf("PACKET : %d\n", ++count);

	 while(len<Pcap->len)
        {
        printf("%02x ", *(p++));
        if(!(++len % 16))
        printf("\n");
        }
	printf("\n");
	printf("Destination Mac:");
	for(i=0;i<6;i++)
	printf(" %02x ",Eth->ether_dhost[i]);
	printf("\n");
	printf("Source Mac:");
	for(i=0;i<6;i++)
	printf(" %02x ",Eth->ether_shost[i]);
        printf("\n");

	printf("Payload : \n");
	while(j<len-sizeof(struct libnet_ethernet_hdr))
	{
		printf(" %02x",(packet[14+(j++)]));
		if(!(j%16))
		printf("\n");
	}
	printf("\n");

	if(ntohs(Eth->ether_type)==ETHERTYPE_IP)
	{
	printf("It's IPv4\n");
	packet+=sizeof(struct libnet_ethernet_hdr);
	Ip=(struct libnet_ipv4_hdr *)(packet);
	printf("Destination IP: %s\n",inet_ntoa(Ip->ip_dst));
	printf("Source IP: %s\n",inet_ntoa(Ip->ip_src));
	
	printf("Payload : \n");
	j=0;
	
	while(j<len-sizeof(struct libnet_ipv4_hdr)-sizeof(struct libnet_ethernet_hdr))
	{
		printf("%02x ",(packet[sizeof(struct libnet_ipv4_hdr)+(j++)]));
		if(!(j%16))
		printf("\n");
	}
	printf("\n");
	if(Ip->ip_p==0x06)
	{
		printf("It's TCP\n");
		packet+=sizeof(struct libnet_ipv4_hdr);
		Tcp=(struct libnet_tcp_hdr*)packet;
		printf("Destination port: %d\n",ntohs(Tcp->th_dport));
		printf("Source port: %d\n", ntohs(Tcp->th_sport));
	}
	}
	
	
	printf("\n");

	return;
}
