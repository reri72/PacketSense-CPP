#include <iostream>
#include <unistd.h>

#include "LogManager.h"
#include "ReadConf.h"
#include "CapturePkt.h"
#include "PacketBlocker.h"
#include "PacketLogger.h"

class CaptureLoggerTest : public PacketListener
{
    public:
        void onPacket(const struct pcap_pkthdr* header, const u_char* packet) override
        {
            std::cout << "Captured packet of length: " << header->len << " bytes" << std::endl;
        }
};

int main(int argc, char **argv)
{
    int opt;
    std::string configFile;

    while ((opt = getopt(argc, argv, "c:")) != -1)
    {
        switch (opt)
        {
            case 'c':
            {
                configFile = optarg;
            } break;

            default:
            {
                std::cerr << "Usage: " << argv[0] << " -c <config_file>" << std::endl;
            } return 1;
        }
    }

    ILOG("Hello ps-cpp!");

    if (configFile.empty())
    {
        CLOG("Config file is required.");
        CLOG("Usage: ps-cpp -c <config_file>");
        return 1;
    }

    ReadConf::getInstance().loadConfig(configFile);
    ReadConf::getInstance().printAllConfig();

#if 0
    try
    {
        std::string targetDev = ReadConf::getInstance().getCaptureInterface();
        bool Promiscuous = ReadConf::getInstance().getPromiscuousMode();
        std::string filterRule = ReadConf::getInstance().getFilterExpres();

        std::unique_ptr<CapturePkt> capturer = std::make_unique<CapturePkt>(targetDev, Promiscuous, filterRule);

        ILOG("Starting packet capture on device: {}", targetDev);
        
        CaptureLoggerTest logger;
        capturer->addObserver(&logger);

        SqliteClient db("ps-cpp.db");
        if (!db.connect())
        {
            ELOG("DB connection failed");
            return -1;
        }

        PacketBlocker blocker(&db);
        if (!blocker.initialize())
        {
            ELOG("PacketBlocker initialization failed");
            return -1;
        }
        capturer->addObserver(&blocker);

        PacketLogger packetlogger(&db);
        if (!packetlogger.initialize())
        {
            ELOG("PacketLogger initialization failed");
            return -1;
        }
        capturer->addObserver(&packetlogger);

        capturer->startCapture();

        int o = 0;
        while (o < 10)
        {
            sleep(1);
            o++;
        }

        capturer->stopCapture();
    }
    catch (const std::exception& ex)
    {
        ELOG("Exception: {}", ex.what());
        return 1;
    }
#endif

    return 0;
}