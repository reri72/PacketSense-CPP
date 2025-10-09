#ifndef _PACKETBLOCKER_H_
#define _PACKETBLOCKER_H_

#include "PacketListener.h"
#include "SqliteClient.h"
#include "DbProcessor.h"

// 옵저버
class PacketBlocker : public DbProcessor
{
    public:
        PacketBlocker(SqliteClient* dbClient);
        ~PacketBlocker();
        void onPacket(const struct pcap_pkthdr* header, const u_char* packet) override;
    
    private:
        sqlite3_stmt* block_stmt;

        int current_retry_count = 0;

        unsigned short checksum(unsigned short *ptr, int nbytes);
        void sendReset(const char* src_ip, const char* dst_ip,
                        uint16_t src_port, uint16_t dst_port,
                        uint32_t seq, uint32_t ack_seq,
                        uint16_t ip_id, uint8_t ttl);
        
        void createTable() override;
        void prepareStatements() override;
        void finalizeStatements() override;
};

#endif