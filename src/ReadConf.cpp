#include <iostream>
#include <fstream>
#include <algorithm>

#include "ReadConf.h"
#include "LogManager.h"

using namespace std;

void ReadConf::loadConfig(const std::string& filename)
{
    ifstream file(filename);

    if (!file.is_open())
    {
        CLOG("There is no file {}", filename);
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
                    m_targetInterface  = value;
                }
                else if (key == PROMISCUOUS)
                {
                    value.erase(remove_if(value.begin(), value.end(), ::isspace), value.end());
                    transform(value.begin(), value.end(), value.begin(), ::toupper);
                    if (value[0] == '1' || value[0] == 'T')
                        m_isPromiscuous  = true;
                    else
                        m_isPromiscuous  = false;
                }
                else if (key == REJECT)
                {
                    value.erase(remove_if(value.begin(), value.end(), ::isspace), value.end());
                    transform(value.begin(), value.end(), value.begin(), ::toupper);
                    if (value[0] == '1' || value[0] == 'T')
                        m_isReject = true;
                    else
                        m_isReject = false;
                }
                else if (key == FILTER)
                {
                    m_filterExpres = value;
                }
                else if (key == REJECTIPS)
                {
                    value.erase(remove_if(value.begin(), value.end(), ::isspace), value.end());
                    StringParser::parseAndInsert(value, ',', m_setRejectIps);
                }
                else if (key == REJECTPORTS)
                {
                    value.erase(remove_if(value.begin(), value.end(), ::isspace), value.end());
                    StringParser::parseAndInsert(value, ',', m_setRejectPorts);
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
    ILOG("{} : {}", INTERFACE, m_targetInterface );

    ILOG("{} : {}", PROMISCUOUS, m_isPromiscuous );

    ILOG("{} : {}", FILTER , m_filterExpres);

    ILOG("{} : {}", REJECT, m_isReject);

    ILOG("{} : ", REJECTIPS);
    for (set<string>::iterator it = m_setRejectIps.begin(); it != m_setRejectIps.end(); it++)
        ILOG("{} ", *it);

    ILOG("{} : ", REJECTPORTS);
    for (set<uint16_t>::iterator it = m_setRejectPorts.begin(); it != m_setRejectPorts.end(); it++)
        ILOG("{} ", *it);
}
