#include <pcap.h>
#include <ifaddrs.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <linux/if.h>
#include <netdb.h>
#include <stdio.h>
#include <string.h>
#include "mac.h"
#include "ip.h"

struct ether_header{
    u_int8_t dest[6];
    u_int8_t src[6];
    u_int8_t type[2];
    // 0806 == ARP
    // 0800 == TCP
};

struct ip_header{
    u_int8_t sender[4];
    u_int8_t target[4];
};

ether_header getEther(const u_char *packet){
    ether_header ether;
    for(int i = 0; i < 6; i++) ether.dest[i] = packet[i];
    for(int i = 0; i < 6; i++) ether.src[i] = packet[i+6];
    ether.type[0] = packet[12];
    ether.type[1] = packet[13];

    return ether;
}

ip_header getIp(const u_char *packet){
    ip_header ip;
    for(int i = 0; i < 4; i++) {
        ip.sender[i] = packet[i+28];
        ip.target[i] = packet[i+38];
    }
    return ip;
}

ip_header otherGetIp(const u_char *packet){
    ip_header ip;
    for(int i = 0; i < 4; i++) {
        ip.sender[i] = packet[i+26];
        ip.target[i] = packet[i+30];
    }
    return ip;
}

u_int32_t changeIp(u_int8_t* ip8){
    u_int32_t ip32 = 0;
    ip32 += ip8[0] << 24;
    ip32 += ip8[1] << 16;
    ip32 += ip8[2] << 8;
    ip32 += ip8[3];

    return ip32;
}

void getMAC(char* interface, u_int8_t* mac){
  struct ifreq s;
  int fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);

  strcpy(s.ifr_name, interface);
  if (0 == ioctl(fd, SIOCGIFHWADDR, &s)) {
      for(int i = 0; i < 6; i++)
          mac[i] = (unsigned char)s.ifr_addr.sa_data[i];
  }
}

Ip getMyIP(char* interface){
    struct ifaddrs *ifaddr, *ifa;
        int s;
        char host[NI_MAXHOST];

        if (getifaddrs(&ifaddr) == -1){
            perror("getifaddrs");
            exit(EXIT_FAILURE);
        }


        for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next){
            if (ifa->ifa_addr == NULL) continue;
            s=getnameinfo(ifa->ifa_addr,sizeof(struct sockaddr_in),host, NI_MAXHOST, NULL, 0, NI_NUMERICHOST);
            if((strcmp(ifa->ifa_name, interface)==0)&&(ifa->ifa_addr->sa_family==AF_INET)){
                if (s != 0){
                    printf("getnameinfo() failed: %s\n", gai_strerror(s));
                    exit(EXIT_FAILURE);
                }
                freeifaddrs(ifaddr);
                return Ip(host);
            }
        }

        freeifaddrs(ifaddr);
}
