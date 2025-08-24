#ifndef _PACKETLISTENER_H_
#define _PACKETLISTENER_H_

#include <pcap.h>

// 옵저버 인터페이스 클래스

class PacketListener
{
    public:
        virtual void onPacket(const struct pcap_pkthdr* header, const u_char* packet) = 0;
        virtual ~PacketListener() = default;
};

#endif