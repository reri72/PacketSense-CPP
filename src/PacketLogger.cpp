#include "PacketLogger.h"
#include "LogManager.h"

#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <net/if_arp.h>
#include <arpa/inet.h>
#include <sstream>

PacketLogger::PacketLogger(SqliteClient* dbClient)
    : DbProcessor(dbClient), tcp_stmt(nullptr), udp_stmt(nullptr), arp_stmt(nullptr)
{
    //
}

PacketLogger::~PacketLogger()
{
    //
}

void PacketLogger::onPacket(const struct pcap_pkthdr* header, const u_char* packet)
{
    if (!_db->isConnected())
    {
        if (!tryReconnect())
        {
            ELOG("Packet logging skipped");
            return;
        }
    }

    bool res = insertPacketData(header, packet);
    if (!res)
    {
        ELOG("Failed insertPacketData. Disconnecting for failover.");
        _db->disconnect(); 
    }
}

void PacketLogger::createTable()
{
    std::string tcpquery = "CREATE TABLE IF NOT EXISTS tcp_table ( \
                            id        INTEGER PRIMARY KEY AUTOINCREMENT, \
                            ts_sec    INTEGER, \
                            ts_usec   INTEGER, \
                            caplen    INTEGER, \
                            pktlen    INTEGER, \
                            src_ip    TEXT, \
                            dst_ip    TEXT, \
                            src_port  INTEGER, \
                            dst_port  INTEGER);";

    _db->executeQuery(tcpquery);
    
    std::string udpquery = "CREATE TABLE IF NOT EXISTS udp_table ( \
                            id          INTEGER PRIMARY KEY AUTOINCREMENT, \
                            ts_sec      INTEGER, \
                            ts_usec     INTEGER, \
                            caplen      INTEGER, \
                            pktlen      INTEGER, \
                            src_ip      TEXT, \
                            dst_ip      TEXT, \
                            src_port    INTEGER, \
                            dst_port    INTEGER, \
                            length      INTEGER );";

    _db->executeQuery(udpquery);

    std::string arpquery = "CREATE TABLE IF NOT EXISTS arp_table ( \
                            id        INTEGER PRIMARY KEY AUTOINCREMENT, \
                            ts_sec    INTEGER, \
                            ts_usec   INTEGER, \
                            caplen    INTEGER, \
                            pktlen    INTEGER, \
                            opcode    INTEGER, \
                            sender_mac TEXT, \
                            sender_ip  TEXT, \
                            target_mac  TEXT, \
                            target_ip   TEXT);";

    _db->executeQuery(arpquery);
}

bool PacketLogger::insertPacketData(const struct pcap_pkthdr* header, const u_char* packet) // 프로토콜 별로 std::string 반환하는 함수 만들면 괜찮겠다. 바인드 써서
{
    const struct ethhdr *eth = (struct ethhdr *)packet;
    uint16_t eth_type = ntohs(eth->h_proto);

    const struct ip *iph = nullptr;
    if (eth_type == 0x0800 || eth_type == 0x8100)
    {
        char src_buf[INET_ADDRSTRLEN] = {0,};
        char dst_buf[INET_ADDRSTRLEN] = {0,};

        if (eth_type == 0x0800)
            iph = (struct ip *)(packet + 14);    // ipv4
        else
            iph = (struct ip *)(packet + 18);    // vlan(802.1Q)

        if (iph->ip_p == IPPROTO_TCP)
        {
            const struct tcphdr* tcph = (struct tcphdr*)((u_char*)iph + iph->ip_hl * 4);

            inet_ntop(AF_INET, &(iph->ip_src), src_buf, sizeof(src_buf));
            inet_ntop(AF_INET, &(iph->ip_dst), dst_buf, sizeof(dst_buf));

            std::string src_ip(src_buf);
            std::string dst_ip(dst_buf);
            
            uint16_t src_port = ntohs(tcph->source);
            uint16_t dst_port = ntohs(tcph->dest);

            if (tcp_stmt) 
            {
                // 바인딩은 1부터 시작
                _db->bindInt(tcp_stmt, 1, header->ts.tv_sec);
                _db->bindInt(tcp_stmt, 2, header->ts.tv_usec);
                _db->bindInt(tcp_stmt, 3, header->caplen);
                _db->bindInt(tcp_stmt, 4, header->len);
                _db->bindText(tcp_stmt, 5, src_ip);
                _db->bindText(tcp_stmt, 6, dst_ip);
                _db->bindInt(tcp_stmt, 7, src_port);
                _db->bindInt(tcp_stmt, 8, dst_port);

                return _db->executeStatement(tcp_stmt);
            }
            return false;
        }
        else if (iph->ip_p == IPPROTO_UDP)
        {
            struct udphdr *uhdr = (struct udphdr *)((u_char*)iph + iph->ip_hl * 4);

            inet_ntop(AF_INET, &(iph->ip_src), src_buf, sizeof(src_buf));
            inet_ntop(AF_INET, &(iph->ip_dst), dst_buf, sizeof(dst_buf));

            std::string src_ip(src_buf);
            std::string dst_ip(dst_buf);

            uint16_t src_port = ntohs(uhdr->source);
            uint16_t dst_port = ntohs(uhdr->dest);
            uint16_t length = ntohs(uhdr->len);
            
            if (udp_stmt) 
            {
                _db->bindInt(udp_stmt, 1, header->ts.tv_sec);
                _db->bindInt(udp_stmt, 2, header->ts.tv_usec);
                _db->bindInt(udp_stmt, 3, header->caplen);
                _db->bindInt(udp_stmt, 4, header->len);
                _db->bindText(udp_stmt, 5, src_ip);
                _db->bindText(udp_stmt, 6, dst_ip);
                _db->bindInt(udp_stmt, 7, src_port);
                _db->bindInt(udp_stmt, 8, dst_port);
                _db->bindInt(udp_stmt, 9, length);

                return _db->executeStatement(udp_stmt);
            }
            return false;
        }
    }
    else if (eth_type == 0x0806) // arp
    {
        if (header->caplen < 14 + sizeof(struct arphdr))
        {
            // 이더헤더랑 arp헤더보다 길이가 작으면 리턴
            return false;
        }

        const struct arphdr *arp = (struct arphdr *)(packet + 14);

        if (ntohs(arp->ar_pro) != 0x0800)
        {
            return false; // ipv4만 처리
        }

        int hlen = arp->ar_hln; // 하드웨어 주소 길이는 보통 6
        int plen = arp->ar_pln; // ipv4 주소 길이는 보통 4
        int opcode = ntohs(arp->ar_op);

        // 실제 데이터 포인터로 이동
        const u_char *ptr = (u_char *)(arp + 1);

        // 최소 길이보다 작은지 확인
        if (header->caplen < 14 + sizeof(struct arphdr) + 2*hlen + 2*plen)
        {
            ELOG("Invalid packet length");
            return false;
        }

        char sender_ip[INET_ADDRSTRLEN] = {0,};
        char target_ip[INET_ADDRSTRLEN] = {0,};
        char sender_mac[18] = {0,};
        char target_mac[18] = {0,};

        snprintf(sender_mac, sizeof(sender_mac), "%02x:%02x:%02x:%02x:%02x:%02x",
                    ptr[0], ptr[1], ptr[2], ptr[3], ptr[4], ptr[5]);
        inet_ntop(AF_INET, ptr + 6, sender_ip, sizeof(sender_ip));

        snprintf(target_mac, sizeof(target_mac), "%02x:%02x:%02x:%02x:%02x:%02x",
                    ptr[10], ptr[11], ptr[12], ptr[13], ptr[14], ptr[15]);
        inet_ntop(AF_INET, ptr + 16, target_ip, sizeof(target_ip));

        if (arp_stmt)
        {
            _db->bindInt(arp_stmt, 1, header->ts.tv_sec);
            _db->bindInt(arp_stmt, 2, header->ts.tv_usec);
            _db->bindInt(arp_stmt, 3, header->caplen);
            _db->bindInt(arp_stmt, 4, header->len);
            _db->bindInt(arp_stmt, 5, opcode);
            _db->bindText(arp_stmt, 6, sender_mac);
            _db->bindText(arp_stmt, 7, sender_ip);
            _db->bindText(arp_stmt, 8, target_mac);
            _db->bindText(arp_stmt, 9, target_ip);
            
            return _db->executeStatement(arp_stmt);
        }
        return false;
    }

    return true;
}

void PacketLogger::prepareStatements()
{
    std::string tcp_sql = "INSERT INTO tcp_table (ts_sec, ts_usec, caplen, pktlen, src_ip, dst_ip, src_port, dst_port) VALUES (?, ?, ?, ?, ?, ?, ?, ?);";
    if (!_db->prepareStatement(tcp_sql, &tcp_stmt))
    {
        ELOG("Failed to prepare TCP statement.");
    }
    
    std::string udp_sql = "INSERT INTO udp_table (ts_sec, ts_usec, caplen, pktlen, src_ip, dst_ip, src_port, dst_port, length) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);";
    if (!_db->prepareStatement(udp_sql, &udp_stmt))
    {
        ELOG("Failed to prepare UDP statement.");
    }

    std::string arp_sql = "INSERT INTO arp_table (ts_sec, ts_usec, caplen, pktlen, opcode, sender_mac, sender_ip, target_mac, target_ip) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);";
    if (!_db->prepareStatement(arp_sql, &arp_stmt))
    {
        ELOG("Failed to prepare ARP statement.");
    }
}

void PacketLogger::finalizeStatements()
{
    if (tcp_stmt) _db->finalizeStatement(tcp_stmt);
    if (udp_stmt) _db->finalizeStatement(udp_stmt);
    if (arp_stmt) _db->finalizeStatement(arp_stmt);

    tcp_stmt = nullptr;
    udp_stmt = nullptr;
    arp_stmt = nullptr;
}
