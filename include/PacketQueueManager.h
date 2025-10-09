#ifndef _PACKETQUEUEMANAGER_H_
#define _PACKETQUEUEMANAGER_H_

#include "PacketListener.h"
#include <pcap.h>
#include <vector>
#include <queue>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <atomic>

// 큐에 저장할 패킷 데이터 구조체
struct QueuedPacket
{
    struct pcap_pkthdr header;
    std::vector<u_char> data; 

    QueuedPacket() = default;

    // 복사 금지
    QueuedPacket(const QueuedPacket&) = delete;
    QueuedPacket& operator=(const QueuedPacket&) = delete;

    // 이동만 허용
    QueuedPacket(QueuedPacket&&) = default;
    QueuedPacket& operator=(QueuedPacket&&) = default;
};

// 비동기 큐 관리 클래스 (소비자 클래스이자 알림자)
class PacketQueueManager
{
    private:
        std::queue<QueuedPacket> queue_; // 버퍼
        std::mutex mtx;
        std::condition_variable cv;
        std::vector<std::thread> workers;
        std::atomic<bool> stop_flag{false};
        
        std::vector<PacketListener *> observers; 
        std::mutex observer_mtx;
        
        void processWorker();

    public:
        PacketQueueManager(int numWorkers = 2);
        ~PacketQueueManager();

        // 생산자 함수
        void enqueue(const struct pcap_pkthdr *header, const u_char *packet);

        void addObserver(PacketListener *observer);
        void removeObserver(PacketListener *observer);

        void startWorkers();
        void stopWorkers();
};

#endif