#include <algorithm>
#include <stdexcept>

#include "PacketQueueManager.h"
#include "LogManager.h"

PacketQueueManager::PacketQueueManager(int numWorkers) 
{
    if (numWorkers > 0)
    {
        ILOG("({}) Workers count : {}", __FUNCTION__, numWorkers);
        workers.reserve(numWorkers);
    }
}

PacketQueueManager::~PacketQueueManager()
{
    stopWorkers();
}

void PacketQueueManager::addObserver(PacketListener *observer)
{
    std::lock_guard<std::mutex> lock(observer_mtx);
    observers.push_back(observer);
}

void PacketQueueManager::removeObserver(PacketListener *observer)
{
    std::lock_guard<std::mutex> lock(observer_mtx);
    observers.erase(
        std::remove(observers.begin(), observers.end(), observer),
        observers.end()
    );
}

void PacketQueueManager::enqueue(const struct pcap_pkthdr *header, const u_char *packet)
{
    QueuedPacket qp;
    qp.header = *header;
    qp.data.assign(packet, packet + header->caplen);

    {
        std::lock_guard<std::mutex> lock(mtx);
        queue_.push(std::move(qp)); // 포인터만 복사
    }

    cv.notify_one();
}

void PacketQueueManager::processWorker()
{
    while (!stop_flag)
    {
        QueuedPacket packet_data;
        {
            // 큐가 비어있지 않거나 종료 신호가 올 때까지 대기
            std::unique_lock<std::mutex> lock(mtx);
            cv.wait(lock, [this]{ return stop_flag.load() || !queue_.empty(); });

            if (stop_flag.load() && queue_.empty())
            {
                return;
            }
            
            packet_data = std::move(queue_.front());
            queue_.pop();
        }

        {
            std::lock_guard<std::mutex> lock(observer_mtx);
            for (PacketListener* obs : observers)
            {
                try
                {
                    obs->onPacket(&(packet_data.header), packet_data.data.data());
                }
                catch (const std::exception& e)
                {
                    ELOG("({}) error in worker thread : {}", __FUNCTION__, e.what());
                }
            }
        }
    }
}

void PacketQueueManager::startWorkers()
{
    if (!workers.empty())
        return;

    int numWorkers = workers.capacity();

    if (numWorkers == 0)
        return;

    ILOG("({}) Starting {} packet processing worker threads",
                                    __FUNCTION__, numWorkers);

    int i = 0;
    for (i = 0; i < numWorkers; ++i)
    {
        workers.emplace_back(&PacketQueueManager::processWorker, this);
    }
}

void PacketQueueManager::stopWorkers()
{
    if (stop_flag.load())
        return;

    stop_flag.store(true);
    cv.notify_all();

    for (std::thread &worker : workers)
    {
        if (worker.joinable())
        {
            worker.join();
        }
    }

    workers.clear();

    ILOG("({}) worker threads stopped", __FUNCTION__);
}
