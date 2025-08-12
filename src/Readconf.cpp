#include <iostream>
#include <fstream>
#include <stdlib.h>

#include "ReadConf.h"

using namespace std;

void ReadConf::loadConfig(const std::string& filename)
{
    std::ifstream file(filename);

    if (!file.is_open())
    {
        cout << "There is no file \"" << filename << "\" " << endl;
        exit(0);
    }
    
    std::string line;
    while (getline(file, line))
    {
        cout << line << endl;
    }

    file.close();
}

void ReadConf::printAllConfig()
{
    //
}