#ifndef _READCONF_H_
#define _READCONF_H_

#include "Singleton.h"
#include <string>
#include <set>
#include <sstream>

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
        #define ITEMSIZE    5

        #define INTERFACE "caputre_interface"
        std::set<std::string> setInterface;

        #define PROMISCUOUS "promiscuous_mode"
        bool IsPromiscuous;

        #define FILTER "capture_filter"
        std::string strFilter;

        #define REJECTIPS "reject_ips"
        std::set<std::string> setRejectIp;

        #define REJECTPORTS "reject_ports"
        std::set<uint16_t> setRejectPort;
};

class StringParser
{
    public:
        template <typename Container>
        static void parseAndInsert(const std::string& row, char unit, Container& container)
        {
            typedef typename Container::value_type T;
            std::stringstream ss(row);
            std::string token;

            while (std::getline(ss, token, unit))
            {
                if (!token.empty())
                {
                    addToken<T>(token, container);
                }
            }
        }

    private:
        template <typename T, typename Container>
        static void addToken(const std::string& token, Container& container)
        {
            addTokenImpl<T>(token, container, std::is_same<T, std::string>());
        }

        template <typename T, typename Container>
        static void addTokenImpl(const std::string& token, Container& container, std::true_type)
        {
            insertToContainer(container, token);
        }

        template <typename T, typename Container>
        static void addTokenImpl(const std::string& token, Container& container, std::false_type)
        {
            std::stringstream conv(token);
            T value;
            if (conv >> value)
            {
                insertToContainer(container, value);
            }
        }
        
        template <typename T>
        static void insertToContainer(std::set<T>& c, const T& v) { c.insert(v); }
};

#endif