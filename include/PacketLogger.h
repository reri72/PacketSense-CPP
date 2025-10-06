#ifndef _PACKETLOGGER_H_
#define _PACKETLOGGER_H_

#include "PacketListener.h"
#include "SqliteClient.h"
#include "DbProcessor.h"

class PacketLogger : public DbProcessor
{
    public:
        PacketLogger(SqliteClient* dbClient);
        ~PacketLogger();
        void onPacket(const struct pcap_pkthdr* header, const u_char* packet) override;
    
    private:
        sqlite3_stmt* tcp_stmt;
        sqlite3_stmt* udp_stmt;
        sqlite3_stmt* arp_stmt;

        int current_retry_count = 0;
        
        void createTable() override;
        void prepareStatements() override;
        void finalizeStatements() override;

        bool insertPacketData(const struct pcap_pkthdr* header, const u_char* packet);
};

#endif