#include "PacketLogger.h"
#include "LogManager.h"

#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <sstream>

PacketLogger::PacketLogger(const std::string& db_file) : _db(db_file)
{
    if (_db.connect())
    {
        ILOG("Successfully connected to database: {}", db_file);
        createTable();
    }
    else
    {
        ELOG("Failed to connect to database: {}", db_file);
    }
}

void PacketLogger::createTable()
{
    std::string query = "CREATE TABLE IF NOT EXISTS ps_table ( \
                            id        INTEGER PRIMARY KEY AUTOINCREMENT, \
                            ts_sec    INTEGER, \
                            ts_usec   INTEGER, \
                            caplen    INTEGER, \
                            pktlen    INTEGER, \
                            src_ip    TEXT, \
                            dst_ip    TEXT, \
                            src_port  INTEGER, \
                            dst_port  INTEGER);";
    _db.executeQuery(query);
}

void PacketLogger::onPacket(const struct pcap_pkthdr* header, const u_char* packet)
{
    insertPacketData(header, packet);
}

void PacketLogger::insertPacketData(const struct pcap_pkthdr* header, const u_char* packet)
{
    const struct ip* iph = (struct ip*)(packet + 14);
    if (iph->ip_p != IPPROTO_TCP)
    {
        return;
    }

    const struct tcphdr* tcph = (struct tcphdr*)((u_char*)iph + iph->ip_hl * 4);

    char src_buf[INET_ADDRSTRLEN] = {0,};
    char dst_buf[INET_ADDRSTRLEN] = {0,};

    inet_ntop(AF_INET, &(iph->ip_src), src_buf, sizeof(src_buf));
    inet_ntop(AF_INET, &(iph->ip_dst), dst_buf, sizeof(dst_buf));

    std::string src_ip(src_buf);
    std::string dst_ip(dst_buf);
    
    uint16_t src_port = ntohs(tcph->source);
    uint16_t dst_port = ntohs(tcph->dest);

    std::ostringstream query;
    query << "INSERT INTO ps_table (ts_sec, ts_usec, caplen, pktlen, src_ip, dst_ip, src_port, dst_port) VALUES ("
          << header->ts.tv_sec << ", "
          << header->ts.tv_usec << ", "
          << header->caplen << ", "
          << header->len << ", '"
          << src_ip << "', '"
          << dst_ip << "', "
          << src_port << ", "
          << dst_port << ");";

    if (_db.executeQuery(query.str()))
    {
        DLOG("Success to insert");
    }
    else
    {
        ELOG("Failed to insert");
    }
}
