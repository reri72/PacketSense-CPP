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

CapturePkt::CapturePkt(const std::string& device, const bool &Promiscuous, const std::string& filter_rule)
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
        WLOG("pcap_open_live : {}", errbuf);
    }

    std::cout << "filter_rule " << filter_rule << std::endl;
    // 네트워크 주소와 서브넷 마스크 조회
    if (pcap_lookupnet(device.c_str(), &net, &mask, errbuf) == -1)
    {
        WLOG("pcap_lookupnet failed '{}' : {}", device, errbuf);
        net = 0;
        mask = 0;
    }

    if (!filter_rule.empty())
    {
        if (pcap_compile(handle, &fp, filter_rule.c_str(), 0, mask) == -1)
        {
            std::string err = pcap_geterr(handle);
            ELOG("pcap_compile failed : {}", err);
            throw std::runtime_error("pcap_compile failed : " + err);
        }

        if (pcap_setfilter(handle, &fp) == -1)
        {
            std::string err = pcap_geterr(handle);
            ELOG("pcap_setfilter failed : {}", err);
            pcap_freecode(&fp); // 메모리 누수 방지
            throw std::runtime_error("pcap_setfilter failed : " + err);
        }

        ILOG("BPF filter '{}' applied successfully on device '{}'.", filter_rule, device);
    }
}

CapturePkt::~CapturePkt()
{
    if (handle)
    {
        pcap_freecode(&fp);
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
