//
// Created by Lake on 2023/1/19.
//

#include "capture.h"
#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <string.h>
#include <netinet/in.h>
#include <unistd.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>

#define SIZE_ETHERNET 14

// Receives NativePort ID from Flutter code
static Dart_Port_DL sendPort = 0;
static Dart_Port recvPort;
static pcap_t* pcap;
static pcap_dumper_t *dumper;
static bool stop = false;

static int linkhdrlen;
static int packets;


void set_dart_port(Dart_Port_DL port)
{
    sendPort = port;
}

void get_link_header_len(pcap_t* handle)
{
    int linktype;
 
    // Determine the datalink layer type.
    if ((linktype = pcap_datalink(handle)) == PCAP_ERROR) {
        fprintf(stderr, "pcap_datalink(): %s\n", pcap_geterr(handle));
        return;
    }
 
    // Set the datalink layer header size.
    switch (linktype)
    {
    case DLT_NULL:
        linkhdrlen = 4;
        break;
 
    case DLT_EN10MB:
        linkhdrlen = 14;
        break;
 
    case DLT_SLIP:
    case DLT_PPP:
        linkhdrlen = 24;
        break;
 
    default:
        printf("Unsupported datalink (%d)\n", linktype);
        linkhdrlen = 0;
    }
}

void send_pkt_info(uint32_t caplen, char * proto, char * src, char * dst) {
    // send packet size
    char msg_str[100];  
    sprintf(msg_str, "caplen:%u;proto:%s;src:%s;dst:%s", caplen, proto, src, dst); // caplen:100000;proto:icmp;src:255.255.255.255;dst:255.255.255.255
    printf("send Msg: %s", msg_str);
    Dart_CObject msg;
    msg.type = Dart_CObject_kString;
    msg.value.as_string = msg_str;
    Dart_PostCObject_DL(sendPort, &msg);
}

void send_isolate_exit_msg() {
    // send packet size
    char msg_str[100];  
    sprintf(msg_str, "isolate:exit"); // caplen:100000;proto:icmp;src:255.255.255.255;dst:255.255.255.255
    printf("send Msg: %s", msg_str);
    Dart_CObject msg;
    msg.type = Dart_CObject_kString;
    msg.value.as_string = msg_str;
    Dart_PostCObject_DL(sendPort, &msg);
}

void pkt_handler(u_char * user, const struct pcap_pkthdr * ph, const u_char * sp) {
    pcap_dump(user, ph, sp);
    if(!sendPort) {
        printf("dart port NOT initialized.");
        return;
    }
    
    if(ph == NULL) return;

    // send packet size
    char msg_str[20];
    sprintf(msg_str, "caplen:%u", ph->caplen);
    Dart_CObject msg;
    msg.type = Dart_CObject_kString;
    msg.value.as_string = msg_str;
    Dart_PostCObject_DL(sendPort, &msg);

}

void packet_handler(u_char *user, const struct pcap_pkthdr *packethdr, const u_char *packetptr)
{
    printf("trace: packet_handler()\n");

    pcap_dump(user, packethdr, packetptr);

    struct ip* iphdr;
    struct icmp* icmphdr;
    struct tcphdr* tcphdr;
    struct udphdr* udphdr;
    char iphdrInfo[256];
    char srcip[256];
    char dstip[256];
 
    // Skip the datalink layer header and get the IP header fields.
    packetptr += linkhdrlen;
    iphdr = (struct ip*)packetptr;
    strcpy(srcip, inet_ntoa(iphdr->ip_src));
    strcpy(dstip, inet_ntoa(iphdr->ip_dst));
    sprintf(iphdrInfo, "ID:%d TOS:0x%x, TTL:%d IpLen:%d DgLen:%d",
            ntohs(iphdr->ip_id), iphdr->ip_tos, iphdr->ip_ttl,
            4*iphdr->ip_hl, ntohs(iphdr->ip_len));
    
    // send_pkt_info(packethdr->caplen, "TCP", srcip, dstip);
 
    // Advance to the transport layer header then parse and display
    // the fields based on the type of hearder: tcp, udp or icmp.
    packetptr += 4*(iphdr->ip_hl);
    switch (iphdr->ip_p)
    {
    case IPPROTO_TCP:
        tcphdr = (struct tcphdr*)packetptr;
        printf("TCP  %s:%d -> %s:%d\n", srcip, ntohs(tcphdr->th_sport),
               dstip, ntohs(tcphdr->th_dport));
        printf("%s\n", iphdrInfo);
        printf("%c%c%c%c%c%c Seq: 0x%x Ack: 0x%x Win: 0x%x TcpLen: %d\n",
               (tcphdr->th_flags & TH_URG ? 'U' : '*'),
               (tcphdr->th_flags & TH_ACK ? 'A' : '*'),
               (tcphdr->th_flags & TH_PUSH ? 'P' : '*'),
               (tcphdr->th_flags & TH_RST ? 'R' : '*'),
               (tcphdr->th_flags & TH_SYN ? 'S' : '*'),
               (tcphdr->th_flags & TH_SYN ? 'F' : '*'),
               ntohl(tcphdr->th_seq), ntohl(tcphdr->th_ack),
               ntohs(tcphdr->th_win), 4*tcphdr->th_off);
        printf("+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+\n\n");
        packets += 1;
        send_pkt_info(packethdr->caplen, "TCP", srcip, dstip);
        break;
 
    case IPPROTO_UDP:
        udphdr = (struct udphdr*)packetptr;
        printf("UDP  %s:%d -> %s:%d\n", srcip, ntohs(udphdr->uh_sport),
               dstip, ntohs(udphdr->uh_dport));
        printf("%s\n", iphdrInfo);
        printf("+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+\n\n");
        packets += 1;
        send_pkt_info(packethdr->caplen, "UDP", srcip, dstip);
        break;
 
    case IPPROTO_ICMP:
        icmphdr = (struct icmp*)packetptr;
        printf("ICMP %s -> %s\n", srcip, dstip);
        printf("%s\n", iphdrInfo);
        printf("Type:%d Code:%d ID:%d Seq:%d\n", icmphdr->icmp_type, icmphdr->icmp_code,
               ntohs(icmphdr->icmp_hun.ih_idseq.icd_id), ntohs(icmphdr->icmp_hun.ih_idseq.icd_seq));
        printf("+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+\n\n");
        packets += 1;
        send_pkt_info(packethdr->caplen, "ICMP", srcip, dstip);
        break;
    }
}

pcap_t* create_pcap_handle(char* device, char* filter)
{
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = NULL;
    pcap_if_t* devices = NULL;
    struct bpf_program bpf;
    bpf_u_int32 netmask;
    bpf_u_int32 srcip;

    // If no network interface (device) is specfied, get the first one.
    if (!*device) {
    	if (pcap_findalldevs(&devices, errbuf)) {
            fprintf(stderr, "pcap_findalldevs(): %s\n", errbuf);
            return NULL;
        }
        strcpy(device, devices[0].name);
    }

    // Get network device source IP address and netmask.
    if (pcap_lookupnet(device, &srcip, &netmask, errbuf) == PCAP_ERROR) {
        fprintf(stderr, "pcap_lookupnet: %s\n", errbuf);
        return NULL;
    }

    // Open the device for live capture.
    handle = pcap_open_live(device, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "pcap_open_live(): %s\n", errbuf);
        return NULL;
    }

    // Convert the packet filter epxression into a packet filter binary.
    if (pcap_compile(handle, &bpf, filter, 0, netmask) == PCAP_ERROR) {
        fprintf(stderr, "pcap_compile(): %s\n", pcap_geterr(handle));
        return NULL;
    }

    // Bind the packet filter to the libpcap handle.
    if (pcap_setfilter(handle, &bpf) == PCAP_ERROR) {
        fprintf(stderr, "pcap_setfilter(): %s\n", pcap_geterr(handle));
        return NULL;
    }

    return handle;
}

int run_capture(void * data, const char * dev, const char * path) {
    printf("start capture\n");
    char filter[256];
    *filter = 0;
    stop = false;
    
    const u_char* pkt;
    struct pcap_pkthdr ph;
    char ebuf[PCAP_ERRBUF_SIZE];
    pcap = pcap_open_live(dev, 65535, 0, 0, ebuf);
    if (!pcap) {
        fprintf(stderr, "%s\n", ebuf);
        return 1;  // 开启抓包失败
    }

    // Get the type of link layer.
    get_link_header_len(pcap);
    printf("%d\n", linkhdrlen);
    if (linkhdrlen == 0) {
        return -1;
    }

    pcap_dumper_t *dumper = pcap_dump_open(pcap, path);

    // int loop_ret = pcap_loop(pcap, 0, &pkt_handler, (u_char *)dumper);
    int loop_ret = pcap_loop(pcap, 0, &packet_handler, (u_char *)dumper);
    if (loop_ret == -1) {
        printf("Error reading packets from interface %s, loop_ret:%d, errMsg:%s\n", dev, loop_ret, pcap_geterr(pcap));
        return 2;  // 抓包过程失败
    }

    pcap_dump_flush(dumper);
    pcap_dump_close(dumper);
    pcap_close(pcap);

    printf("before stoped capture\n");

    send_isolate_exit_msg();
 
    printf("stoped capture\n");
    return 0;
}

int stop_capture() {
    stop = true;
    pcap_breakloop(pcap);
    // Dart_ExitIsolate();
    return 0;
}


// int main() {
//     run_capture("en0", "./capture.pcap");
// }