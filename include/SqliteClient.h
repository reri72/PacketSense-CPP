#ifndef _SQLITECLIENT_H_
#define _SQLITECLIENT_H_

#include <sqlite3.h>
#include <string>
#include <vector>
#include <mutex>

class SqliteClient
{
    public:
        SqliteClient(const std::string& db_file);
        ~SqliteClient();
        
        bool connect();
        void disconnect();
        bool executeQuery(const std::string& query);
        std::vector<std::vector<std::string>> fetchQuery(const std::string& query);

    private:
        sqlite3* _db;
        std::string dbfile;
        std::mutex mtx;
};

#endif