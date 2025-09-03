#include <iostream>
#include <unistd.h>

#include "LogManager.h"
#include "ReadConf.h"
#include "SqliteClient.h"
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

    ILOG("Hello ps-cpp!");

    if (configFile.empty())
    {
        WLOG("Config file is required.");
        WLOG("Usage: ps-cpp -c <config_file>");
        return 1;
    }

    ReadConf::getInstance().loadConfig(configFile);
    ReadConf::getInstance().printAllConfig();

#if 0
    SqliteClient db("ps-cpp.db");
    if (!db.connect())
    {
        return 1;
    }

    db.executeQuery("CREATE TABLE IF NOT EXISTS ps_table ( \
                        id        INTEGER PRIMARY KEY AUTOINCREMENT, \
                        ts_sec    INTEGER, \
                        ts_usec   INTEGER, \
                        caplen    INTEGER, \
                        pktlen    INTEGER, \
                        src_mac   TEXT, \
                        dst_mac   TEXT, \
                        src_ip    TEXT, \
                        dst_ip    TEXT, \
                        src_port  INTEGER, \
                        dst_port  INTEGER);");

    db.executeQuery("INSERT INTO ps_table VALUES (1, 1693560000, 123456, 60, 60, \"AA:BB:CC:DD:EE:FF\", \"11:22:33:44:55:66\", \"192.168.0.1\", \"192.168.0.100\", 12345, 80);");
    db.executeQuery("INSERT INTO ps_table VALUES (2, 1693560000, 123456, 60, 60, \"AA:BB:CC:DD:EE:FF\", \"11:22:33:44:55:66\", \"192.168.0.1\", \"192.168.0.100\", 12345, 90);");

    std::vector<std::vector<std::string>> rows = db.fetchQuery("SELECT * FROM ps_table;");

    std::size_t i = 0;
    for (i = 0; i < rows.size(); ++i)
    {
        std::vector<std::string> row = rows[i];
        std::cout << "id : " << row[0] << std::endl;
    }

    db.disconnect();
#endif

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