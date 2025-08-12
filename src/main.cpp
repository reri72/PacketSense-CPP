#include <iostream>
#include <unistd.h>

#include "ReadConf.h"

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

    return 0;
}