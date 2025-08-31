#include <iostream>
#include <unistd.h>

#include "ReadConf.h"
#include "CapturePkt.h"

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

    if (configFile.empty())
    {
        std::cerr << "Config file is required." << std::endl;
        std::cerr << "Usage: " << argv[0] << " -c <config_file>" << std::endl;
        return 1;
    }

    ReadConf::getInstance().loadConfig(configFile);
    ReadConf::getInstance().printAllConfig();

#if 0
    try
    {
        std::string targetDev = ReadConf::getInstance().getCaptureInterface();
        bool Promiscuous = ReadConf::getInstance().getPromiscuousMode();

        CapturePkt capturer(targetDev, Promiscuous);

        CaptureLoggerTest logger;
        capturer.addObserver(&logger);

        std::cout << "Starting packet capture on device: " << targetDev << std::endl;
        capturer.startCapture();
    }
    catch (const std::exception& ex)
    {
        std::cerr << "Exception: " << ex.what() << std::endl;
        return 1;
    }
#endif

    return 0;
}