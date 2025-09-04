#include <iostream>
#include <sstream>
#include <thread>

#include "CapturePkt.h"
#include "LogManager.h"

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
            ELOG("PacketListener error: {}", e.what());
        }
    }
}

CapturePkt::CapturePkt(const std::string& device, const bool &Promiscuous)

{
    char errbuf[PCAP_ERRBUF_SIZE] = {0,};

    handle = pcap_open_live(device.c_str(), BUFSIZ, Promiscuous, 1000, errbuf);
    if (!handle)
    {
        ELOG("pcap_open_live() failed on device '{}' : {}", device, errbuf);
        throw std::runtime_error(
                    std::string("pcap_open_live() failed on device '(") + device + ")': " + errbuf
        );
    }

    if (errbuf[0] != '\0')
    {
        WLOG("pcap_open_live: {}", errbuf);
    }
}

CapturePkt::~CapturePkt()
{
    if (handle)
    {
        pcap_close(handle);
    }
}

void CapturePkt::startCapture()
{
    std::thread t(&CapturePkt::captureThread, this);
    t.detach();
}

void CapturePkt::captureThread()
{
    //                                                  userData
    if (pcap_loop(handle, 0, packetHandler, reinterpret_cast<u_char*>(this)) < 0)
    {
        ELOG("{}", (std::string("pcap_loop() failed: ") + pcap_geterr(handle)));
    }
}

void CapturePkt::stopCapture()
{
    pcap_breakloop(handle);
}

void CapturePkt::packetHandler(u_char* userData, const struct pcap_pkthdr* header, const u_char* packet)
{
    CapturePkt* capturer = reinterpret_cast<CapturePkt*>(userData);
    if (!capturer) return;

    capturer->handlePacket(header, packet);
}

void CapturePkt::handlePacket(const struct pcap_pkthdr* header, const u_char* packet)
{
    DLOG("Captured at: {}.{}, len: {}, caplen: {}",
        header->ts.tv_sec,
        header->ts.tv_usec,
        header->len,
        header->caplen
        );

    std::ostringstream oss;
    unsigned int i = 0;

    for (i = 0; i < header->caplen; i++)
    {
        oss << std::hex
            << std::setw(2)
            << std::setfill('0')
            << static_cast<int>(packet[i])
            << " ";

        if ((i + 1) % 16 == 0)
            oss << "\n";
    }

    DLOG("hex: {}", oss.str());

    notify(header, packet);
}
