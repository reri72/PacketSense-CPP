#include "CapturePkt.h"
#include <iostream>

void PacketNotifier::addObserver(PacketListener* observer)
{
    std::lock_guard<std::mutex> lock(mtx);
    observers.push_back(observer);
}

void PacketNotifier::removeObserver(PacketListener* observer)
{
    std::lock_guard<std::mutex> lock(mtx);
    observers.erase(
        remove(observers.begin(), observers.end(), observer),
        observers.end()
    );
}

void PacketNotifier::notify(const struct pcap_pkthdr* header, const u_char* packet)
{
    std::lock_guard<std::mutex> lock(mtx);
    for (PacketListener* obs : observers)
    {
        try
        {
            obs->onPacket(header, packet);
        }
        catch (const std::exception& e)
        {
            std::cerr << "PacketListener error: " << e.what() << std::endl;
        }
    }
}

CapturePkt::CapturePkt(const std::string& device, const bool &Promiscuous)

{
    char errbuf[PCAP_ERRBUF_SIZE] = {0,};

    handle = pcap_open_live(device.c_str(), BUFSIZ, Promiscuous, 1000, errbuf);
    if (!handle)
    {
        throw std::runtime_error(
                    std::string("pcap_open_live() failed on device '(") + device + ")': " + errbuf
        );
    }

    if (errbuf[0] != '\0')
    {
        std::cerr << "[WARN] pcap_open_live: " << errbuf << std::endl;
    }
}

CapturePkt::~CapturePkt()
{
    if (handle)
    {
        pcap_close(handle);
    }
}

void CapturePkt::startCapture(int packetCount)
{
    //                                                  userData
    if (pcap_loop(handle, packetCount, packetHandler, reinterpret_cast<u_char*>(this)) < 0)
    {
        throw std::runtime_error(std::string("pcap_loop() failed: ") + pcap_geterr(handle));
    }
}

void CapturePkt::stopCapture()
{
    pcap_breakloop(handle);
}

void CapturePkt::packetHandler(u_char* userData, const struct pcap_pkthdr* header, const u_char* packet)
{
    CapturePkt* capturer = reinterpret_cast<CapturePkt*>(userData);

    std::cout << "Captured at: " << header->ts.tv_sec
            << "." << header->ts.tv_usec
            << " len: " << header->len
            << " caplen: " << header->caplen
            << std::endl;

    capturer->notify(header, packet);
}

