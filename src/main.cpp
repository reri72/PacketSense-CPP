#include <iostream>
#include <csignal>
#include <atomic>
#include <unistd.h>
#include <sys/types.h>

#include "LogManager.h"
#include "ReadConf.h"
#include "CapturePkt.h"
#include "PacketBlocker.h"
#include "PacketLogger.h"
#include "PacketQueueManager.h"

std::atomic<bool> running(true);

class CaptureLoggerTest : public PacketListener
{
    public:
        void onPacket(const struct pcap_pkthdr* header, const u_char* packet) override
        {
            std::cout << "Captured packet of length: " << header->len << " bytes" << std::endl;
        }
};

void sig_handle(int signum)
{
    running = false;

    std::cout << signum << " received.." <<std::endl;
    ILOG("signal {} received..", signum);
}

int main(int argc, char **argv)
{
    if (geteuid() != 0)
    {
        std::cout << "root privileges are required" << std::endl;
        exit(0);
    }

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

    struct sigaction sa = {0,};

    sa.sa_handler = sig_handle;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;

    sigaction(SIGINT, &sa, nullptr);
    sigaction(SIGTERM, &sa, nullptr);
    sigaction(SIGHUP, &sa, nullptr);
    sigaction(SIGABRT, &sa, nullptr);
    sigaction(SIGPIPE, &sa, nullptr);

    ILOG("Hello ps-cpp!");

    if (configFile.empty())
    {
        CLOG("Config file is required.");
        CLOG("Usage: ps-cpp -c <config_file>");
        return 1;
    }

    ReadConf::getInstance().loadConfig(configFile);
    ReadConf::getInstance().printAllConfig();

    try
    {
        const int num_workers = 2;
        PacketQueueManager queueManager(num_workers);

        std::string targetDev = ReadConf::getInstance().getCaptureInterface();
        bool Promiscuous = ReadConf::getInstance().getPromiscuousMode();
        std::string filterRule = ReadConf::getInstance().getFilterExpres();

        std::unique_ptr<CapturePkt> capturer = 
            std::make_unique<CapturePkt>(targetDev, Promiscuous, filterRule, &queueManager);

        ILOG("Starting packet capture on device: {}", targetDev);
        
        // 콘솔 출력을 위한 클래스
        CaptureLoggerTest logger;
        queueManager.addObserver(&logger);

        // SQLite 데이터베이스 관련
        SqliteClient db("ps-cpp.db");
        if (!db.connect())
        {
            ELOG("DB connection failed");
            return -1;
        }

        // 패킷 차단을 위한 클래스
        PacketBlocker blocker(&db);
        if (!blocker.initialize())
        {
            ELOG("PacketBlocker initialization failed");
            return -1;
        }
        queueManager.addObserver(&blocker);

        // 캡처한 패킷의 정보를 처리하는 클래스
        PacketLogger packetlogger(&db);
        if (!packetlogger.initialize())
        {
            ELOG("PacketLogger initialization failed");
            return -1;
        }
        queueManager.addObserver(&packetlogger);

        queueManager.startWorkers();
        capturer->startCapture();

        while (running)
        {
            sleep(1);
        }

        capturer->stopCapture();
        queueManager.stopWorkers();
    }
    catch (const std::exception& ex)
    {
        ELOG("Exception: {}", ex.what());
        return 1;
    }

    return 0;
}