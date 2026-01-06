
#include <netinet/in.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <pcap/pcap.h>


int link_hdr_length = 14; 

void call_me(u_char *user, const struct pcap_pkthdr *pkthdr, const u_char *packet_ptr) {
    packet_ptr += link_hdr_length;
    struct  ip *ip_hdr = (struct ip *) packet_ptr; 
    
    char packet_srcip[INET_ADDRSTRLEN]; 
    char packet_dstip[INET_ADDRSTRLEN];           
    strcpy(packet_srcip, inet_ntoa(ip_hdr->ip_src));
    strcpy(packet_dstip, inet_ntoa(ip_hdr->ip_dst));
    int packet_id = ntohs(ip_hdr->ip_id),
      packet_ttl = ip_hdr->ip_ttl,
      packet_tos = ip_hdr->ip_tos,
      packet_len = ntohs(ip_hdr->ip_len),
      packet_hlen = ip_hdr->ip_hl;



    
    printf("************************************" "************************************\n");
    printf("ID: %d | SRC: %s | DST: %s | TOS: 0x%x | TTL: %d\n", packet_id, 
    packet_srcip, packet_dstip, packet_tos, packet_ttl); 

    packet_ptr += (4 * packet_hlen); 
    int protocol_type = ip_hdr -> ip_p; 


    struct  tcphdr * tcp_header; 
    struct udphdr * udp_header; 
    struct icmp * icmp_header; 
    int src_port, dst_port; 

    switch (protocol_type){
        case IPPROTO_TCP:
            tcp_header = (struct tcphdr *) packet_ptr; 
            src_port = tcp_header -> th_sport; 
            dst_port = tcp_header -> th_dport; 
            printf("PROTO: TCP | FLAGS: %c/%c/%c | SPORT: %d | DPORT: %d |\n",
             (tcp_header->th_flags & TH_SYN ? 'S' : '-'),
             (tcp_header->th_flags & TH_ACK ? 'A' : '-'),
             (tcp_header->th_flags & TH_URG ? 'U' : '-'), src_port, dst_port);
             break;
        case IPPROTO_UDP:
            udp_header = (struct udphdr *) packet_ptr; 
            src_port = udp_header -> uh_sport; 
            dst_port = udp_header-> uh_dport;
            printf("PROTO: UDP | SPORT: %d | DPORT: %d |\n", src_port, dst_port); 
            break;
        case IPPROTO_ICMP:
            icmp_header = (struct icmp *) packet_ptr; 
            int icmp_type = icmp_header-> icmp_type; 
            int icmp_type_code = icmp_header-> icmp_code; 
            printf("PROTO: ICMP | TYPE: %d | CODE: %d |\n", icmp_type, icmp_type_code);
            break;


    }

}

    int main(int argc, char const *argv[]){

/*
Declare the device name and error buffer size
*/
char *device = "en0"; 
char error_buffer[PCAP_ERRBUF_SIZE]; 
int packets_count = 100; 

pcap_t *capdev = pcap_open_live(device, BUFSIZ, 1, 100, error_buffer); 

if (capdev == NULL){
    printf("ERR: pcap_open_live() %s\n", error_buffer); 
    exit(1);

}

if (pcap_loop(capdev, packets_count, call_me, (u_char *)NULL)){
    printf("ERR: pcap_loop() failed! \n");
    exit(1);
}
return 0; 
}
   