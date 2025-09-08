#ifndef _PACKETBLOCKER_H_
#define _PACKETBLOCKER_H_

#include "PacketListener.h"

class PacketBlocker : public PacketListener
{
    public:
        void onPacket(const struct pcap_pkthdr* header, const u_char* packet) override;
    
    private:
        unsigned short checksum(unsigned short *ptr, int nbytes);
        void send_rst(const char* src_ip, const char* dst_ip,
                        uint16_t src_port, uint16_t dst_port,
                        uint32_t seq, uint32_t ack_seq,
                        uint16_t ip_id, uint8_t ttl);
};

#endif