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
        
        const std::string &getCaptureInterface() const { return m_targetInterface ; }
        void setCaptureInterface(std::string interface) { m_targetInterface  = interface; }

        bool getPromiscuousMode() const { return m_isPromiscuous ; }
        void setPromiscuousMode(const bool mode) { m_isPromiscuous  = mode; }

        const std::string &getFilterExpres() const {return m_filterExpres; }
        void setFilterExpres(const std::string& filter) { m_filterExpres = filter; }

        bool getReject() const { return m_isReject; }
        void setReject(bool reject) { m_isReject = reject; }

        const std::set<std::string> &getRejectIPs() const { return m_setRejectIps; }
        void setRejectIPs(const std::set<std::string> &ips) { m_setRejectIps = ips; }

        const std::set<uint16_t>& getRejectPorts() const { return m_setRejectPorts; }
        void setRejectPorts(const std::set<uint16_t>& ports) { m_setRejectPorts = ports; }

    private:
        ReadConf() = default;
        ~ReadConf() = default;

    private:
        #define ITEMSIZE    5

        static constexpr const char* const INTERFACE = "capture_interface";
        std::string m_targetInterface ;

        static constexpr const char* const PROMISCUOUS = "promiscuous_mode";
        bool m_isPromiscuous = false;

        static constexpr const char* const FILTER = "capture_filter";
        std::string m_filterExpres;

        static constexpr const char* const REJECT = "reject";
        bool m_isReject = false;

        static constexpr const char* const REJECTIPS = "reject_ips";
        std::set<std::string> m_setRejectIps;

       static constexpr const char* const REJECTPORTS = "reject_ports";
        std::set<uint16_t> m_setRejectPorts;
};

class StringParser
{
    public:
        template <typename Container>
        static void parseAndInsert(const std::string& row, char unit, Container& container)
        {
            // 대부분의 STL 컨테이너는 원소 타입을 value_type 이라는 이름으로 제공
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