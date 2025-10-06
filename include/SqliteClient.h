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
        bool isConnected() const;
        
        bool executeQuery(const std::string& query);
        std::vector<std::vector<std::string>> fetchQuery(const std::string& query);

        bool prepareStatement(const std::string& sql, sqlite3_stmt **stmt);
        bool bindText(sqlite3_stmt *stmt, int index, const std::string& value);
        bool bindInt(sqlite3_stmt *stmt, int index, int value);
        bool executeStatement(sqlite3_stmt *stmt);
        void finalizeStatement(sqlite3_stmt *stmt);

    private:
        sqlite3* _db;
        std::string dbfile;
        std::mutex mtx;
};

#endif