#ifndef PACKET_HEADERS_H
#define PACKET_HEADERS_H

#include <netinet/in.h>  // for struct in_addr
#include <stdint.h>

#define ETHER_ADDR_LEN 6
#define PCAP_ERRBUF_SIZE 256

// Ethernet Header
struct libnet_ethernet_hdr {
    uint8_t  ether_dhost[ETHER_ADDR_LEN];  // destination ethernet address
    uint8_t  ether_shost[ETHER_ADDR_LEN];  // source ethernet address
    uint16_t ether_type;                   // protocol
};

// IPv4 Header
struct libnet_ipv4_hdr {
#if __BYTE_ORDER == __LITTLE_ENDIAN
    uint8_t ip_hl:4,      // header length
        ip_v:4;       // version
#elif __BYTE_ORDER == __BIG_ENDIAN
    uint8_t ip_v:4,
        ip_hl:4;
#else
#error "Byte ordering not specified"
#endif
    uint8_t ip_tos;
    uint16_t ip_len;
    uint16_t ip_id;
    uint16_t ip_off;
    uint8_t ip_ttl;
    uint8_t ip_p;
    uint16_t ip_sum;
    struct in_addr ip_src, ip_dst;
};

// TCP Header
struct libnet_tcp_hdr {
    uint16_t th_sport;  // source port
    uint16_t th_dport;  // destination port
    uint32_t th_seq;
    uint32_t th_ack;
#if __BYTE_ORDER == __LITTLE_ENDIAN
    uint8_t th_x2:4,
        th_off:4;
#elif __BYTE_ORDER == __BIG_ENDIAN
    uint8_t th_off:4,
        th_x2:4;
#else
#error "Byte ordering not specified"
#endif
    uint8_t  th_flags;
    uint16_t th_win;
    uint16_t th_sum;
    uint16_t th_urp;
};

#endif // PACKET_HEADERS_H
