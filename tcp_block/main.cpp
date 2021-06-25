#include <pcap.h>
#include <stdio.h>
#include <libnet.h>

#define TRUE 1
#define FALSE 0

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

//find warning site
int warning(const u_char* buf, char* site) {
    int i;
    const u_char* packet = buf;

    libnet_ipv4_hdr *ip_hdr_v4 = (libnet_ipv4_hdr*)(packet);
    libnet_tcp_hdr *tcp_hdr = (libnet_tcp_hdr *)(packet + (ip_hdr_v4->ip_hl*4));
    int data_size = ntohs(ip_hdr_v4->ip_len) - ip_hdr_v4->ip_hl*4 - tcp_hdr->th_off*4;

    printf("[dump] data size : %d ip_hdr_v4 : %d \n", data_size, ip_hdr_v4->ip_hl*4);

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
                printf("warning site : %s", site);

                if(strncmp(ptr, site, strlen(site)) == 0){
                    printf("find it %s", ptr);
                    return TRUE;
                }
            }
        }
    }
    return FALSE;
}



int main(int argc, char* argv[]) {
    int index = 1;

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
            //send block packet
        }

        index++;
        printf("\n");
    }

    pcap_close(pcap);
}
