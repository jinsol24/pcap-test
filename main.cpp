#include <iostream>
#include <pcap.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <cstring>
#include <iomanip>
#include "packet_headers.h"

using namespace std;

// MAC 주소 문자열로 출력
void print_mac(const u_int8_t* mac) {
    for (int i = 0; i < 6; ++i) {
        printf("%02x", mac[i]);
        if (i < 5) printf(":");
    }
}


void packet_handler(u_char* user, const struct pcap_pkthdr* header, const u_char* packet) {
    auto eth = (struct libnet_ethernet_hdr*)packet; // 패킷의 처음 부분에 위치하는 Ethernet 헤더

    if (ntohs(eth->ether_type) != 0x0800) return; // IPv4만

    auto ip = (struct libnet_ipv4_hdr*)(packet + sizeof(libnet_ethernet_hdr)); // Ethernet 헤더 다음에 위치하는 IPv4 헤더
    if (ip->ip_p != IPPROTO_TCP) return; // TCP만

    int ip_header_len = ip->ip_hl * 4;
    auto tcp = (struct libnet_tcp_hdr*)((u_char*)ip + ip_header_len); // TCP 헤더
    int tcp_header_len = tcp->th_off * 4;

    const u_char* payload = (u_char*)tcp + tcp_header_len; // 페이로드
    int total_len = ntohs(ip->ip_len);
    int payload_len = total_len - ip_header_len - tcp_header_len;

    // 출력
    printf("====================================\n");

    // Ethernet
    printf("Ethernet Header\n");
    printf("    Src MAC: ");
    print_mac(eth->ether_shost);
    printf("\n    Dst MAC: ");
    print_mac(eth->ether_dhost);
    printf("\n");

    // IP
    printf("IP Header\n");
    printf("    Src IP: %s\n", inet_ntoa(ip->ip_src));
    printf("    Dst IP: %s\n", inet_ntoa(ip->ip_dst));

    // TCP
    printf("TCP Header\n");
    printf("    Src Port: %u\n", ntohs(tcp->th_sport));
    printf("    Dst Port: %u\n", ntohs(tcp->th_dport));

    // Payload (최대 20바이트만 출력)
    printf("Payload (Hex, max 20 bytes):\n    ");
    for (int i = 0; i < payload_len && i < 20; ++i) {
        printf("%02x ", payload[i]);
    }
    printf("\n");
}

int main(int argc, char* argv[]) {
    if (argc != 2) {
        cerr << "에러: 네트워크 인터페이스 이름을 입력해주세요.";
        return 1;
    }

    char errbuf[PCAP_ERRBUF_SIZE];
    const char* dev = argv[1];

    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf); // 모든 패킷 수신
    if (!handle) {
        cerr << "에러: 네트워크 장치 " << dev << "를(을) 열 수 없습니다.\n";
        cerr << "상세 내용: " << errbuf << "\n";
        return 1;
    }

    // 패킷 캡처 루프 시작
    while (true) {
        struct pcap_pkthdr* header; // 패킷의 메타데이터를 담는 구조체
        const u_char* packet; // 실제 패킷 데이터
        int res = pcap_next_ex(handle, &header, &packet);
        if (res == 0) continue;
        if (res == -1 || res == -2) break; // 에러나 종료
        packet_handler(nullptr, header, packet);
    }

    pcap_close(handle);
    return 0;
}

