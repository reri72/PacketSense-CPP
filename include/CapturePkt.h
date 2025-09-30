#ifndef _CAPTUREPKT_H_
#define _CAPTUREPKT_H_

#include <pcap.h>
#include <vector>
#include <mutex>
#include <string>
#include <algorithm>
#include "PacketListener.h"

// 알림 주체 클래스
class PacketNotifier
{
    private:
        std::vector<PacketListener*> observers;
        std::mutex mtx;

    public:
        void addObserver(PacketListener* observer);
        void removeObserver(PacketListener* observer);
        void notify(const struct pcap_pkthdr* header, const u_char* packet);
};

// 콘크리트 클래스
class CapturePkt : public PacketNotifier
{
    private:
        pcap_t* handle;
        
        struct bpf_program fp;
        bpf_u_int32 net;
        bpf_u_int32 mask;

        static void packetHandler(u_char* userData,
                                const struct pcap_pkthdr* header,
                                const u_char* packet);
        void handlePacket(const struct pcap_pkthdr* header,
                                const u_char* packet);

    public:
        CapturePkt(const std::string& device, const bool &Promiscuous, const std::string& filter_rule = "");
        ~CapturePkt();

        void startCapture();
        void captureThread();
        void stopCapture();
};

#endif
