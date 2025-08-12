#ifndef _READCONF_H_
#define _READCONF_H_

#include "Singleton.h"
#include <string>
#include <set>

class ReadConf : public Singleton<ReadConf>
{
    // 친구 클래스로 선언해야 private 생성자에 접근 가능
    friend class Singleton<ReadConf>;

    public:
        void loadConfig(const std::string& filename);
        void printAllConfig();
        
        const std::set<std::string> getCaptureInterfaces() { return setInterface; }
        void setCaptureInterfaces(std::set<std::string>& interfaces) { setInterface = interfaces; }

        const bool getPromiscuousMode() { return IsPromiscuous; }
        void setPromiscuousMode(const bool& mode) { IsPromiscuous = mode; }

        const std::string getFilterExpres() {return strFilter; }
        void setFilterExpres(const std::string& filter) { strFilter = filter; }

        const std::set<std::string> getRejectIPs() { return setRejectIp; }
        void setRejectIPs(const std::set<std::string> &ips) { setRejectIp = ips; }

        const std::set<uint16_t>& getRejectPorts() { return setRejectPort; }
        void setRejectPorts(const std::set<uint16_t>& ports) { setRejectPort = ports; }

    private:
        ReadConf(){};
        ~ReadConf(){};

    private:

        std::set<std::string> setInterface;
        bool IsPromiscuous;
        std::string strFilter;
        std::set<std::string> setRejectIp;
        std::set<uint16_t> setRejectPort;
};


#endif