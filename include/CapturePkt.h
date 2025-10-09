#ifndef _CAPTUREPKT_H_
#define _CAPTUREPKT_H_

#include <pcap.h>
#include <vector>
#include <mutex>
#include <string>
#include <algorithm>
#include "PacketQueueManager.h"

// 생산자 클래스
class CapturePkt
{
    private:
        pcap_t* handle;
        
        struct bpf_program fp;
        bpf_u_int32 net;
        bpf_u_int32 mask;

        std::thread captureThread_;

        PacketQueueManager *queueManager = nullptr;

        static void packetHandler(u_char* userData,
                                const struct pcap_pkthdr* header,
                                const u_char* packet);
        void handlePacket(const struct pcap_pkthdr* header,
                                const u_char* packet);

    public:
        CapturePkt(const std::string& device,
                    bool Promiscuous,
                    const std::string& filter_rule,
                    PacketQueueManager *queueManager);
        ~CapturePkt();

        void startCapture();
        void captureThread();
        void stopCapture();
};

#endif
