#include "PacketBlocker.h"
#include "ReadConf.h"
#include "LogManager.h"

#include <iostream>
#include <string>
#include <set>

#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <net/if_arp.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>

void PacketBlocker::onPacket(const struct pcap_pkthdr* header, const u_char* packet)
{
    const struct ethhdr *eth = (struct ethhdr *)packet;
    uint16_t eth_type = ntohs(eth->h_proto);

    const struct ip *iph = nullptr;
    if (eth_type == 0x0800)
    {
        iph = (struct ip *)(packet + 14);   // ipv4
    }
    else if (eth_type == 0x8100)
    {
        iph = (struct ip *)(packet + 18);    // vlan(802.1Q)
    }
    else
    {
        return;
    }

    if (iph->ip_p != IPPROTO_TCP)
    {
        return;
    }

    const struct tcphdr* tcph = (struct tcphdr*)((u_char*)iph + iph->ip_hl * 4);

    char src_buf[INET_ADDRSTRLEN] = {0,};
    char dst_buf[INET_ADDRSTRLEN] = {0,};

    if (inet_ntop(AF_INET, &(iph->ip_src), src_buf, sizeof(src_buf)) == nullptr)
    {
        ELOG("inet_ntop (ip src)");
        return;
    }

    if (inet_ntop(AF_INET, &(iph->ip_dst), dst_buf, sizeof(dst_buf)) == nullptr)
    {
        ELOG("inet_ntop (ip dst)");
        return;
    }

    std::string src_ip(src_buf);
    std::string dst_ip(dst_buf);

    uint16_t src_port = ntohs(tcph->source);
    uint16_t dst_port = ntohs(tcph->dest);

    const std::set<std::string> &rejectIps = ReadConf::getInstance().getRejectIPs();
    const std::set<uint16_t> &rejectPorts = ReadConf::getInstance().getRejectPorts();

    if (rejectIps.find(src_ip) != rejectIps.end() && rejectPorts.find(dst_port) != rejectPorts.end())
    {
        ILOG("Reset tcp session {}:{} -> {}:{}", dst_ip, dst_port, src_ip, src_port);

        uint16_t ip_id = ntohs(iph->ip_id);
        uint8_t ttl    = iph->ip_ttl;

        // client -> server
        send_rst(src_ip.c_str(), dst_ip.c_str(), src_port, dst_port, ntohl(tcph->seq), ntohl(tcph->ack_seq), ip_id, ttl);

        // server -> client
        send_rst(dst_ip.c_str(), src_ip.c_str(), dst_port, src_port, ntohl(tcph->ack_seq), ntohl(tcph->seq) + 1, ip_id, ttl);
    }
}

unsigned short PacketBlocker::checksum(unsigned short *ptr, int nbytes)
{
    int datalen = nbytes;
    int sum = 0;

    unsigned short *p = ptr;
    unsigned short res = 0;

    while (datalen > 1) 
    {
        sum += *p++;
        datalen -= (sizeof(unsigned short));
    }

    if (datalen == 1) 
    {
        *(unsigned short *)(&res) = *(unsigned short *)p;
        sum += res;
    }

    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    res = ~sum;

    return res;
}

void PacketBlocker::send_rst(const char* src_ip, const char* dst_ip,
                                uint16_t src_port, uint16_t dst_port,
                                uint32_t seq, uint32_t ack_seq,
                                uint16_t ip_id, uint8_t ttl)
{
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (sock < 0)
    {
        ELOG("socket error");
        return;
    }

    int one = 1;

    // raw 소켓으로 직접 ip 헤더 만들어 보내려면 설정해줘야 함
    if (setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0)
    {
        ELOG("setsockopt error");
        close(sock);
        return;
    }

    char packet[4096] = {0,};
    struct ip *iph = (struct ip *)packet;
    struct tcphdr *tcph = (struct tcphdr *) (packet + sizeof(struct ip));

    // IP 헤더
    iph->ip_hl = 5;
    iph->ip_v = 4;
    iph->ip_tos = 0;
    iph->ip_len = htons(sizeof(struct ip) + sizeof(struct tcphdr));
    iph->ip_id = htons(ip_id);
    iph->ip_off = 0;
    iph->ip_ttl = ttl;
    iph->ip_p = IPPROTO_TCP;
    iph->ip_src.s_addr = inet_addr(src_ip);
    iph->ip_dst.s_addr = inet_addr(dst_ip);

    // TCP 헤더
    tcph->source = htons(src_port);
    tcph->dest = htons(dst_port);
    tcph->seq = htonl(seq);
    tcph->ack_seq = htonl(ack_seq);
    tcph->doff = 5;
    tcph->rst = 1;
    tcph->window = htons(128);

    struct pseudo_header
    {
        uint32_t src_addr;
        uint32_t dst_addr;
        uint8_t zero;
        uint8_t protocol;
        uint16_t tcp_length;
    } psh;

    psh.src_addr = iph->ip_src.s_addr;
    psh.dst_addr = iph->ip_dst.s_addr;
    psh.zero = 0;
    psh.protocol = IPPROTO_TCP;
    psh.tcp_length = htons(sizeof(struct tcphdr));

    int psize = sizeof(struct pseudo_header) + sizeof(struct tcphdr);
    char *pseudo = new char[psize];

    memcpy(pseudo, &psh, sizeof(struct pseudo_header));
    memcpy(pseudo + sizeof(struct pseudo_header), tcph, sizeof(struct tcphdr));

    tcph->check = checksum((unsigned short*)pseudo, psize);
    delete[] pseudo;

    iph->ip_sum = checksum((unsigned short *)packet, sizeof(struct ip));

    struct sockaddr_in sin;
    sin.sin_family = AF_INET;
    sin.sin_port = tcph->dest;
    sin.sin_addr.s_addr = iph->ip_dst.s_addr;

    if (sendto(sock, packet, sizeof(struct ip) + sizeof(struct tcphdr), 0, (struct sockaddr *)&sin, sizeof(sin)) < 0)
    {
        ELOG("sendto failed");
    }
    else
    {
        ILOG("RST packet to {}:{}", dst_ip, dst_port);
    }

    close(sock);
}
