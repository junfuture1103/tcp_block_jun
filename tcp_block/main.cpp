#include <pcap.h>
#include <stdio.h>
#include <libnet.h>
#include "ethhdr.h"
#include "arphdr.h"

#define TRUE 1
#define FALSE 0
#define MESSAGE_SIZE 10

#pragma pack(push, 1)

struct EthArpPacket final {
    EthHdr eth_;
    ArpHdr arp_;
};

struct tcp_data{
    char msg[MESSAGE_SIZE];
    int msg_size = MESSAGE_SIZE;
};

struct EthPacket{
    EthHdr eth_;
    libnet_ipv4_hdr ip_hdr_v4;
    libnet_tcp_hdr tcp_hdr;
    tcp_data data;
};

struct Pseudoheader{
    uint32_t srcIP;
    uint32_t destIP;
    uint8_t reserved=0;
    uint8_t protocol;
    uint16_t TCPLen;
};

#pragma pack(pop)
#define CARRY 65536

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

//for test
void dump(unsigned char* buf, int size) {
    int i;
    for (i = 0; i < size; i++) {
        if (i != 0 && i % 16 == 0)
            printf("\n");
        printf("%02X ", buf[i]);
    }
    printf("\n");
}

uint16_t calculate(uint16_t* data, int dataLen)
{
    uint16_t result;
    int tempChecksum=0;
    int length;
    bool flag=false;
    if((dataLen%2)==0)
        length=dataLen/2;
    else
    {
        length=(dataLen/2)+1;
        flag=true;
    }

    for (int i = 0; i < length; ++i) // cal 2byte unit
    {


        if(i==length-1&&flag) //last num is odd num
            tempChecksum+=ntohs(data[i]&0x00ff);
        else
            tempChecksum+=ntohs(data[i]);

        if(tempChecksum>CARRY)
                tempChecksum=(tempChecksum-CARRY)+1;

    }

    result=tempChecksum;
    return result;
}

uint16_t calIPChecksum(uint8_t* data)
{
    struct iphdr* iph=(struct iphdr*)data;
    iph->check=0;//set Checksum field 0

    uint16_t checksum=calculate((uint16_t*)iph,iph->ihl*4);
    iph->check=htons(checksum^0xffff);//xor checksum

    return iph->check;
}

uint16_t calTCPChecksum(uint8_t *data,int dataLen) //data는 ip헤더 시작위치, datalen은 ip헤더 부터 끝까지 길이
{
    //make Pseudo Header
    struct Pseudoheader pseudoheader; //saved by network byte order

    //init Pseudoheader
    struct iphdr *iph=(struct iphdr*)data;
    struct tcphdr *tcph=(struct tcphdr*)(data+iph->ihl*4);

    //Pseudoheader initialize
    memcpy(&pseudoheader.srcIP,&iph->saddr,sizeof(pseudoheader.srcIP));
    memcpy(&pseudoheader.destIP,&iph->daddr,sizeof(pseudoheader.destIP));
    pseudoheader.protocol=iph->protocol;
    pseudoheader.TCPLen=htons(dataLen-(iph->ihl*4));

    //Cal pseudoChecksum
    uint16_t pseudoResult=calculate((uint16_t*)&pseudoheader,sizeof(pseudoheader));

    //Cal TCP Segement Checksum
    tcph->check=0; //set Checksum field 0
    uint16_t tcpHeaderResult=calculate((uint16_t*)tcph,ntohs(pseudoheader.TCPLen));


    uint16_t checksum;
    int tempCheck;

    if((tempCheck=pseudoResult+tcpHeaderResult)>CARRY)
        checksum=(tempCheck-CARRY) +1;
    else
        checksum=tempCheck;


    checksum=ntohs(checksum^0xffff); //xor checksum
    tcph->check=checksum;

    return checksum;
}

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

void SendPacket(pcap_t* handle, const u_char* packet, int packet_size){
    printf("================== sending packet ==================\n");
    dump((u_char*)packet, packet_size);
    int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(packet), packet_size);
    if (res != 0) {
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
    }else{
        printf("Sending block packet..\n");
    }
}

void forward_rst(Mac MAC_ADD, pcap_t* handle, const u_char* buf){
    libnet_ethernet_hdr *eth_hdr = (libnet_ethernet_hdr*)buf;
    libnet_ipv4_hdr *ip_hdr_v4 = (libnet_ipv4_hdr*)(buf + sizeof(libnet_ethernet_hdr));
    libnet_tcp_hdr *tcp_hdr = (libnet_tcp_hdr*)(buf + sizeof(libnet_ethernet_hdr) + (ip_hdr_v4->ip_hl*4));

    int packet_size = sizeof(libnet_ethernet_hdr) + ntohs(ip_hdr_v4->ip_len);
    int tcp_data_size = ntohs(ip_hdr_v4->ip_len) - ip_hdr_v4->ip_hl*4 - tcp_hdr->th_off*4;

    printf("================== origin packet ==================\n");
    dump((u_char*)buf, packet_size);

    EthPacket* packet = (EthPacket*)buf;

    //set ether header
    packet->eth_.dmac_ = Mac(eth_hdr->ether_dhost);//d_mac is org-packet
    packet->eth_.smac_ = Mac(MAC_ADD);
    packet->eth_.type_ = eth_hdr->ether_type;

    //set ip header
    packet->ip_hdr_v4.ip_len = ntohs(sizeof(libnet_ipv4_hdr) + sizeof(libnet_tcp_hdr)); //Here is RST block total length
    packet->ip_hdr_v4.ip_dst = ip_hdr_v4->ip_dst; //d_ip is org-packet
    packet->ip_hdr_v4.ip_src = ip_hdr_v4->ip_src; //s_ip is org-packet
    packet->ip_hdr_v4.ip_ttl = ip_hdr_v4->ip_ttl; //ttl is org-packet
    packet->ip_hdr_v4.ip_sum = calIPChecksum((u_int8_t*)ip_hdr_v4);

    //set tcp header
    packet->tcp_hdr.th_dport = tcp_hdr->th_dport;//sport, dport is org-packet
    packet->tcp_hdr.th_sport = tcp_hdr->th_sport;//sport, dport is org-packet
    packet->tcp_hdr.th_seq = tcp_hdr->th_seq + tcp_data_size;
    packet->tcp_hdr.th_ack = tcp_hdr->th_ack;
    packet->tcp_hdr.th_off = sizeof(libnet_tcp_hdr)/4;
    packet->tcp_hdr.th_flags = TH_RST | TH_ACK; //Rst block. Fin : tcp_hdr_pk->th_flags = TH_FIN | TH_ACK | TH_PSH;
    packet->tcp_hdr.th_sum = calTCPChecksum((u_int8_t*)ip_hdr_v4, ntohs(packet->ip_hdr_v4.ip_len));

    printf("================== made packet ==================\n");
    packet_size = sizeof(libnet_ethernet_hdr) + htons(packet->ip_hdr_v4.ip_len);
    dump((u_char*)packet, packet_size);

    SendPacket(handle, (const u_char*)packet, packet_size);
}


void backward_rst(Mac MAC_ADD, pcap_t* handle, const u_char* buf){
    libnet_ethernet_hdr *eth_hdr = (libnet_ethernet_hdr*)buf;
    libnet_ipv4_hdr *ip_hdr_v4 = (libnet_ipv4_hdr*)(buf + sizeof(libnet_ethernet_hdr));
    libnet_tcp_hdr *tcp_hdr = (libnet_tcp_hdr*)(buf + sizeof(libnet_ethernet_hdr) + (ip_hdr_v4->ip_hl*4));

    int packet_size = sizeof(libnet_ethernet_hdr) + ntohs(ip_hdr_v4->ip_len);
    int tcp_data_size = ntohs(ip_hdr_v4->ip_len) - ip_hdr_v4->ip_hl*4 - tcp_hdr->th_off*4;

    printf("================== origin packet ==================\n");
    dump((u_char*)buf, packet_size);

    EthPacket* packet = (EthPacket*)buf;

    //set ether header
    packet->eth_.dmac_ = Mac(eth_hdr->ether_shost);//d_mac is org-packet
    packet->eth_.smac_ = Mac(MAC_ADD);
    packet->eth_.type_ = eth_hdr->ether_type;

    //set ip header
    packet->ip_hdr_v4.ip_len = ntohs(sizeof(libnet_ipv4_hdr) + sizeof(libnet_tcp_hdr)); //Here is RST block total length
    packet->ip_hdr_v4.ip_dst = ip_hdr_v4->ip_src; //d_ip is org-packet reverse
    packet->ip_hdr_v4.ip_src = ip_hdr_v4->ip_dst; //s_ip is org-packet reverse
    packet->ip_hdr_v4.ip_ttl = 128; //ttl is about 128
    packet->ip_hdr_v4.ip_sum = calIPChecksum((u_int8_t*)ip_hdr_v4);

    //set tcp header
    packet->tcp_hdr.th_dport = tcp_hdr->th_sport;//sport, dport is org-packet
    packet->tcp_hdr.th_sport = tcp_hdr->th_dport;//sport, dport is org-packet
    packet->tcp_hdr.th_seq = tcp_hdr->th_ack;
    packet->tcp_hdr.th_ack = tcp_hdr->th_seq + tcp_data_size;
    packet->tcp_hdr.th_off = sizeof(libnet_tcp_hdr)/4;
    packet->tcp_hdr.th_flags = TH_RST | TH_ACK; //Rst block. Fin : tcp_hdr_pk->th_flags = TH_FIN | TH_ACK | TH_PSH;
    packet->tcp_hdr.th_sum = calTCPChecksum((u_int8_t*)ip_hdr_v4, ntohs(packet->ip_hdr_v4.ip_len));

    printf("================== made packet ==================\n");
    dump((u_char*)packet, packet_size);

    SendPacket(handle, (const u_char*)packet, packet_size);
}

void forward_fin(Mac MAC_ADD, pcap_t* handle, const u_char* buf){
    libnet_ethernet_hdr *eth_hdr = (libnet_ethernet_hdr*)buf;
    libnet_ipv4_hdr *ip_hdr_v4 = (libnet_ipv4_hdr*)(buf + sizeof(libnet_ethernet_hdr));
    libnet_tcp_hdr *tcp_hdr = (libnet_tcp_hdr*)(buf + sizeof(libnet_ethernet_hdr) + (ip_hdr_v4->ip_hl*4));

    int packet_size = sizeof(libnet_ethernet_hdr) + ntohs(ip_hdr_v4->ip_len);

    std::string message = "blocked";

    printf("================== origin packet ==================\n");
    dump((u_char*)buf, packet_size);

    EthPacket* packet = (EthPacket*)buf;

    //set ether header
    packet->eth_.dmac_ = Mac(eth_hdr->ether_dhost);//d_mac is org-packet
    packet->eth_.smac_ = Mac(MAC_ADD);
    packet->eth_.type_ = eth_hdr->ether_type;

    //set ip header
    packet->ip_hdr_v4.ip_len = ntohs(sizeof(libnet_ipv4_hdr) + sizeof(libnet_tcp_hdr) + message.size()); //Here is RST block total length
    packet->ip_hdr_v4.ip_dst = ip_hdr_v4->ip_dst; //d_ip is org-packet
    packet->ip_hdr_v4.ip_src = ip_hdr_v4->ip_src; //s_ip is org-packet
    packet->ip_hdr_v4.ip_ttl = ip_hdr_v4->ip_ttl; //ttl is org-packet
    packet->ip_hdr_v4.ip_sum = calIPChecksum((u_int8_t*)ip_hdr_v4);

    //set tcp header
    packet->tcp_hdr.th_dport = tcp_hdr->th_dport;//sport, dport is org-packet
    packet->tcp_hdr.th_sport = tcp_hdr->th_sport;//sport, dport is org-packet
    packet->tcp_hdr.th_seq = tcp_hdr->th_seq + message.size();
    packet->tcp_hdr.th_ack = tcp_hdr->th_ack;
    packet->tcp_hdr.th_off = sizeof(libnet_tcp_hdr)/4;
    packet->tcp_hdr.th_flags = TH_FIN | TH_ACK | TH_PUSH; //Fin block
    packet->tcp_hdr.th_sum = calTCPChecksum((u_int8_t*)ip_hdr_v4, ntohs(packet->ip_hdr_v4.ip_len));

    //set tcp data
    memcpy(packet->data.msg, message.c_str(), message.size());
    packet->data.msg_size = message.size();

    printf("================== made packet ==================\n");
    packet_size = sizeof(libnet_ethernet_hdr) + htons(packet->ip_hdr_v4.ip_len);
    dump((u_char*)packet, packet_size);

    SendPacket(handle, (const u_char*)packet, packet_size);
}

void backward_fin(Mac MAC_ADD, pcap_t* handle, const u_char* buf){
    libnet_ethernet_hdr *eth_hdr = (libnet_ethernet_hdr*)buf;
    libnet_ipv4_hdr *ip_hdr_v4 = (libnet_ipv4_hdr*)(buf + sizeof(libnet_ethernet_hdr));
    libnet_tcp_hdr *tcp_hdr = (libnet_tcp_hdr*)(buf + sizeof(libnet_ethernet_hdr) + (ip_hdr_v4->ip_hl*4));

    int packet_size = sizeof(libnet_ethernet_hdr) + ntohs(ip_hdr_v4->ip_len);

    printf("================== origin packet ==================\n");
    dump((u_char*)buf, packet_size);

    EthPacket* packet = (EthPacket*)buf;

    std::string message = "blocked";

    //set ether header
    packet->eth_.dmac_ = Mac(eth_hdr->ether_shost);//d_mac is org-packet
    packet->eth_.smac_ = Mac(MAC_ADD);
    packet->eth_.type_ = eth_hdr->ether_type;

    //set ip header
    packet->ip_hdr_v4.ip_len = ntohs(sizeof(libnet_ipv4_hdr) + sizeof(libnet_tcp_hdr) + message.size()); //Here is RST block total length
    packet->ip_hdr_v4.ip_dst = ip_hdr_v4->ip_src; //d_ip is org-packet reverse
    packet->ip_hdr_v4.ip_src = ip_hdr_v4->ip_dst; //s_ip is org-packet reverse
    packet->ip_hdr_v4.ip_ttl = 128; //ttl is about 128
    packet->ip_hdr_v4.ip_sum = calIPChecksum((u_int8_t*)ip_hdr_v4);

    int tcp_data_size = packet->ip_hdr_v4.ip_len - ip_hdr_v4->ip_hl*4 - tcp_hdr->th_off*4;

    //set tcp header
    packet->tcp_hdr.th_dport = tcp_hdr->th_sport;//sport, dport is org-packet
    packet->tcp_hdr.th_sport = tcp_hdr->th_dport;//sport, dport is org-packet
    packet->tcp_hdr.th_seq = tcp_hdr->th_ack;
    packet->tcp_hdr.th_ack = tcp_hdr->th_seq + tcp_data_size;
    packet->tcp_hdr.th_off = sizeof(libnet_tcp_hdr)/4;
    packet->tcp_hdr.th_flags = TH_FIN | TH_ACK | TH_PUSH; //Fin block
    packet->tcp_hdr.th_sum = calTCPChecksum((u_int8_t*)ip_hdr_v4, ntohs(packet->ip_hdr_v4.ip_len));

    //set tcp data
    memcpy(packet->data.msg, message.c_str(), message.size());

    packet->data.msg_size = message.size();
    printf("================== made packet ==================\n");
    packet_size = sizeof(libnet_ethernet_hdr) + htons(packet->ip_hdr_v4.ip_len);
    dump((u_char*)packet, packet_size);

    SendPacket(handle, (const u_char*)packet, packet_size);
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
            //forward_rst(MAC_ADD, pcap, packet);
            //backward_rst(MAC_ADD, pcap, packet);
            forward_fin(MAC_ADD, pcap, packet);
            //backward_fin(MAC_ADD, pcap, packet);

        }

        index++;
        printf("\n");
    }

    pcap_close(pcap);
}
