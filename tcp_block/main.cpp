#include <pcap.h>
#include <stdio.h>
#include <libnet.h>
#include "ethhdr.h"
#include "arphdr.h"

#define TRUE 1
#define FALSE 0

#pragma pack(push, 1)

struct EthArpPacket final {
    EthHdr eth_;
    ArpHdr arp_;
};
#pragma pack(pop)

struct Param {
    char* dev_{nullptr};
    char* site{nullptr};

    bool parse(int argc, char* argv[]) { //function in structure
        if (argc != 3) {
            usage();
            return false;
        }
        dev_ = argv[1];
        site = argv[2];
        return true;
    }

    static void usage() {
        printf("syntax: tcp-block <interface> <pattern>\n");
        printf("sample: tcp-block wlan0 test.gilgil.net\n");
    }
};

//my IP/MAC address
int GetInterfaceMacAddress(const char *ifname, Mac *mac_addr, Ip* ip_addr){
    struct ifreq ifr;
    int sockfd, ret;

    //printf("Get interface(%s) MAC address..\n", ifname);

    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if(sockfd < 0){
        printf("Fail to get\n");
        return -1;
    }

    strncpy(ifr.ifr_name, ifname, IFNAMSIZ);
    ret = ioctl(sockfd, SIOCGIFHWADDR, &ifr);
    if (ret < 0){
        printf("Fail to get\n");
        close(sockfd);
        return -1;
    }
    memcpy((void*)mac_addr, ifr.ifr_hwaddr.sa_data, Mac::SIZE);

    ret = ioctl(sockfd, SIOCGIFADDR, &ifr);
    if (ret < 0){
        printf("Fail to get\n");
        close(sockfd);
        return -1;
    }
    char ipstr[40];
    //memcpy((void*)ip_addr, ifr.ifr_addr.sa_data, Ip::SIZE);
    inet_ntop(AF_INET, ifr.ifr_addr.sa_data+2, ipstr, sizeof(struct sockaddr));
    *ip_addr = Ip(ipstr);

    printf("sucess get interface(%s) & MAC/IP\n", ifname);
    close(sockfd);
    return 0;
}

void SendPacket(pcap_t* handle, EthHdr* packet, int packet_size){
    int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(packet), packet_size);
    if (res != 0) {
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
    }else{
        printf("Sending forward_rst block packet..\n");
    }
}

void forward_rst(Mac MAC_ADD, pcap_t* handle, const u_char* buf){
    libnet_ethernet_hdr *eth_hdr = (libnet_ethernet_hdr*)buf;
    libnet_ipv4_hdr *ip_hdr_v4 = (libnet_ipv4_hdr*)(buf + sizeof(libnet_ethernet_hdr));
    libnet_tcp_hdr *tcp_hdr = (libnet_tcp_hdr*)(buf + sizeof(libnet_ethernet_hdr) + (ip_hdr_v4->ip_hl*4));

    int packet_size = sizeof(libnet_ethernet_hdr) + ntohs(ip_hdr_v4->ip_len);
    int tcp_data_size = ntohs(ip_hdr_v4->ip_len) - ip_hdr_v4->ip_hl*4 - tcp_hdr->th_off*4;

    EthHdr* packet = (EthHdr*)malloc(packet_size);
    libnet_ipv4_hdr *ip_hdr_v4_pk = (libnet_ipv4_hdr*)(packet + sizeof(libnet_ethernet_hdr));
    libnet_tcp_hdr *tcp_hdr_pk = (libnet_tcp_hdr*)(packet + sizeof(libnet_ethernet_hdr) + (ip_hdr_v4->ip_hl*4));


    //set ether header
    packet->dmac_ = Mac(eth_hdr->ether_dhost);//d_mac is org-packet
    //packet->smac_ = Mac(MAC_ADD);
    packet->smac_ = Mac("AA:BB:CC:DD:EE:FF");
    packet->type_ = eth_hdr->ether_type;

    //set ip header
    ip_hdr_v4_pk->ip_len = sizeof(libnet_ipv4_hdr) + sizeof(libnet_ethernet_hdr); //Here is RST block
    ip_hdr_v4_pk->ip_dst = ip_hdr_v4->ip_dst; //d_ip is org-packet
    ip_hdr_v4_pk->ip_src = ip_hdr_v4->ip_src; //s_ip is org-packet
    ip_hdr_v4_pk->ip_ttl = ip_hdr_v4->ip_ttl; //ttl is org-packet
    ip_hdr_v4_pk->ip_sum = ip_hdr_v4->ip_sum;

    //set tcp header
    tcp_hdr_pk->th_dport = tcp_hdr->th_dport;//sport, dport is org-packet
    tcp_hdr_pk->th_sport = tcp_hdr->th_sport;//sport, dport is org-packet
    tcp_hdr_pk->th_seq = tcp_hdr->th_seq + tcp_data_size;
    tcp_hdr_pk->th_ack = tcp_hdr->th_ack;
    tcp_hdr_pk->th_off = tcp_hdr->th_off;
    tcp_hdr_pk->th_flags = TH_RST | TH_ACK; //Fin : tcp_hdr_pk->th_flags = TH_FIN | TH_ACK | TH_PSH;
    tcp_hdr_pk->th_sum = tcp_hdr->th_sum;

    SendPacket(handle, packet, packet_size);
    free(packet);
}

//find warning site
int warning(const u_char* buf, char* site) {
    int i;
    const u_char* packet = buf;

    libnet_ipv4_hdr *ip_hdr_v4 = (libnet_ipv4_hdr*)(packet);
    libnet_tcp_hdr *tcp_hdr = (libnet_tcp_hdr *)(packet + (ip_hdr_v4->ip_hl*4));
    int data_size = ntohs(ip_hdr_v4->ip_len) - ip_hdr_v4->ip_hl*4 - tcp_hdr->th_off*4;

    printf("[is it warning?] data size : %d ip_hdr_v4 : %d \n", data_size, ip_hdr_v4->ip_hl*4);

    if(data_size != 0){
        packet = packet + tcp_hdr->th_off*4 + ip_hdr_v4->ip_hl*4;

        if (packet[0] == 'G'){ //POST? "GET "로 필터링하기
            printf("\n==========http request===========\n");
            printf("\n");
            for (i = 0; i < data_size; i++) {
                if (i != 0 && i % 16 == 0)
                    printf("\n");
                printf("%02X ", packet[i]);
            }
            printf("\n");

            char* ptr = strstr((char*)packet, "Host: "); //strstr,, Host: 없으면 \0 나올때까지 계속감 -> strnstr
            if (ptr !=NULL){
                ptr = ptr + strlen("Host: ");
                ptr = strtok(ptr, "\r\n"); //strtok도 마찬가지 없으면 \0 나올때까지 계속감 ~ 수동으로 찾기
                printf("\nHOST_BY_JUN : %s\n", ptr);
                printf("warning site : %s\n", site);

                if(strncmp(ptr, site, strlen(site)) == 0){
                    printf("find it %s\n", ptr);
                    return TRUE;
                }
            }
        }
    }
    return FALSE;
}

int main(int argc, char* argv[]) {
    int index = 1;

    //My interface
    Mac MAC_ADD;
    Ip IP_ADD;

    Param param;
    if (!param.parse(argc, argv))
        return -1;

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
    if (pcap == nullptr) {
        fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
        return -1;
    }

    while (true) {
        struct pcap_pkthdr* header;
        libnet_ethernet_hdr *eth_hdr;

        const u_char* packet;

        int res = pcap_next_ex(pcap, &header, &packet);
        if (res == 0) continue;
        if (res == -1 || res == -2) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
            break;
        }

        //hdr
        eth_hdr = (libnet_ethernet_hdr*)packet;
        libnet_ipv4_hdr *ip_hdr_v4 = (libnet_ipv4_hdr*)(packet + sizeof(libnet_ethernet_hdr));

        if (ntohs(eth_hdr->ether_type) != ETHERTYPE_IP){
            printf("PASS! type : %X\n", ntohs(eth_hdr->ether_type));
            continue;
        }
        if(ip_hdr_v4->ip_p != IPPROTO_TCP){
            printf("PASS! protocol : %X\n", ip_hdr_v4->ip_p);
            continue;
        }

        printf("[%d] %u bytes captured\n",index, header->caplen);

        //is it warning?? check == 1 -> True check == 0 -> False
        if(warning(packet + sizeof(libnet_ethernet_hdr), param.site)){
            //GetInterface
            if(GetInterfaceMacAddress(param.dev_, &MAC_ADD, &IP_ADD) != 0){
                printf("have problem in GetMAC..\n");
            }

            //send block packet
            forward_rst(MAC_ADD, pcap, packet);
        }

        index++;
        printf("\n");
    }

    pcap_close(pcap);
}
