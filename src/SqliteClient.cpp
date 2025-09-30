#include "SqliteClient.h"
#include "LogManager.h"

#include <iostream>

SqliteClient::SqliteClient(const std::string& db_file) 
    : 
    _db(nullptr), 
    dbfile(db_file)
{
    //
}

SqliteClient::~SqliteClient()
{
    disconnect();
}

bool SqliteClient::connect()
{
    int res = sqlite3_open(dbfile.c_str(), &_db);

    if (res != SQLITE_OK)
    {
        ELOG("Can't open database: {}", sqlite3_errmsg(_db));
        return false;
    }

    return true;
}

void SqliteClient::disconnect()
{
    if (_db != nullptr)
    {
        sqlite3_close(_db);
        _db = nullptr;
    }
}

bool SqliteClient::executeQuery(const std::string& query)
{
    std::lock_guard<std::mutex> lock(mtx);

    char *errmsg = nullptr;
    int res = sqlite3_exec(_db, query.c_str(), nullptr, nullptr, &errmsg);

    if (res != SQLITE_OK)
    {
        ELOG("SQL error: {}", errmsg);
        sqlite3_free(errmsg);
        return false;
    }

    return true;
}

std::vector<std::vector<std::string>> SqliteClient::fetchQuery(const std::string& query)
{
    std::lock_guard<std::mutex> lock(mtx);
    
    std::vector<std::vector<std::string>> results;
    sqlite3_stmt *stmt = nullptr;

    int res = sqlite3_prepare_v2(_db, query.c_str(), -1, &stmt, nullptr);
    if (res != SQLITE_OK)
    {
        ELOG("Failed to prepare statement: {}", sqlite3_errmsg(_db));
        return results;
    }

    while (sqlite3_step(stmt) == SQLITE_ROW)
    {
        int cols = sqlite3_column_count(stmt);
        int i = 0;
        std::vector<std::string> row;

        for (i = 0; i < cols; i++)
        {
            const char* text = reinterpret_cast<const char*>(sqlite3_column_text(stmt, i));
            if (text != nullptr)
            {
                row.push_back(std::string(text));
            }
            else
            {
                row.push_back("");
            }
        }
        results.push_back(row);
    }
    sqlite3_finalize(stmt);
    
    return results;
}
