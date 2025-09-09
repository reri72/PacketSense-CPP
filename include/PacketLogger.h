#ifndef _PACKETLOGGER_H_
#define _PACKETLOGGER_H_

#include "PacketListener.h"
#include "SqliteClient.h"

class PacketLogger : public PacketListener
{
    public:
        PacketLogger(const std::string &db_file);
        void onPacket(const struct pcap_pkthdr* header, const u_char* packet) override;
    
    private:
        SqliteClient _db;
        void createTable();
        void insertPacketData(const struct pcap_pkthdr* header, const u_char* packet);
};

#endif