#include <iostream>
#include <fstream>
#include <algorithm>

#include "ReadConf.h"

using namespace std;

void ReadConf::loadConfig(const std::string& filename)
{
    ifstream file(filename);

    if (!file.is_open())
    {
        cout << "There is no file \"" << filename << "\" " << endl;
        exit(0);
    }
    
    string line;

    int i = 0;
    for (i = 0; i < ITEMSIZE; i++)
    {
        while (getline(file, line))
        {
            line.erase(0, line.find_first_not_of(" \t\n\r"));
            line.erase(line.find_last_not_of(" \t\n\r") + 1);

            size_t eq_pos = line.find('=');
            if (eq_pos != string::npos)
            {
                string key = line.substr(0, eq_pos);
                key.erase(0, key.find_first_not_of(" \t\n\r"));
                key.erase(key.find_last_not_of(" \t\n\r") + 1);

                string value = line.substr(eq_pos + 1);

                if (key == INTERFACE)
                {
                    value.erase(remove_if(value.begin(), value.end(), ::isspace), value.end());
                    StringParser::parseAndInsert(value, ',', setInterface);
                }
                else if (key == PROMISCUOUS)
                {
                    value.erase(remove_if(value.begin(), value.end(), ::isspace), value.end());
                    transform(value.begin(), value.end(), value.begin(), ::toupper);
                    if (value[0] == '1' || value[0] == 'T')
                        IsPromiscuous = true;
                    else
                        IsPromiscuous = false;
                }
                else if (key == FILTER)
                {
                    strFilter = value;
                }
                else if (key == REJECTIPS)
                {
                    value.erase(remove_if(value.begin(), value.end(), ::isspace), value.end());
                    StringParser::parseAndInsert(value, ',', setRejectIp);
                }
                else if (key == REJECTPORTS)
                {
                    value.erase(remove_if(value.begin(), value.end(), ::isspace), value.end());
                    StringParser::parseAndInsert(value, ',', setRejectPort);
                }
                else
                {
                    break;
                }
            }
        }
        file.seekg(0, ios::beg);
    }

    file.close();
}

void ReadConf::printAllConfig()
{
    cout << INTERFACE << " : ";
    for (set<string>::iterator it = setInterface.begin(); it != setInterface.end(); it++)
        cout << *it  << " ";
    cout << endl;

    cout << PROMISCUOUS << " : " << IsPromiscuous << endl;

    cout << FILTER << " : " << strFilter << endl;

    cout << REJECTIPS << " : ";
    for (set<string>::iterator it = setRejectIp.begin(); it != setRejectIp.end(); it++)
        cout << *it  << " ";
    cout << endl;

    cout << REJECTPORTS << " : ";
    for (set<uint16_t>::iterator it = setRejectPort.begin(); it != setRejectPort.end(); it++)
        cout << *it  << " ";
    cout << endl;
}
