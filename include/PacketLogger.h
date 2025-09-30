#ifndef _PACKETLOGGER_H_
#define _PACKETLOGGER_H_

#include "PacketListener.h"
#include "SqliteClient.h"

class PacketLogger : public PacketListener
{
    public:
        PacketLogger(const std::string &db_file);
        ~PacketLogger();
        void onPacket(const struct pcap_pkthdr* header, const u_char* packet) override;
    
    private:
        SqliteClient _db;

        sqlite3_stmt* tcp_stmt;
        sqlite3_stmt* udp_stmt;
        sqlite3_stmt* arp_stmt;

        int current_retry_count = 0;
        
        bool tryReconnect();
        void createTable();
        bool insertPacketData(const struct pcap_pkthdr* header, const u_char* packet);
        void prepareStatements();
};

#endif