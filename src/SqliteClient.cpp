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
    std::lock_guard<std::mutex> lock(mtx); 

    if (_db != nullptr)
        return true;

    int res = sqlite3_open(dbfile.c_str(), &_db);

    if (res != SQLITE_OK)
    {
        ELOG("Can't open database: {}", sqlite3_errmsg(_db));
        _db = nullptr;
        return false;
    }

    return true;
}

void SqliteClient::disconnect()
{
    std::lock_guard<std::mutex> lock(mtx); 

    if (_db != nullptr)
    {
        sqlite3_close(_db);
        _db = nullptr;
    }
}

bool SqliteClient::isConnected() const
{
    return (_db != nullptr);
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

bool SqliteClient::prepareStatement(const std::string& sql, sqlite3_stmt **stmt)
{
    std::lock_guard<std::mutex> lock(mtx);

    // 마지막 인수를 null 로 주어 전체 sql을 컴파일
    int res = sqlite3_prepare_v2(_db, sql.c_str(), -1, stmt, nullptr);
    if (res != SQLITE_OK)
    {
        ELOG("Failed sqlite3_prepare_v2 : {}", sqlite3_errmsg(_db));
        return false;
    }

    return true;
}

bool SqliteClient::bindText(sqlite3_stmt *stmt, int index, const std::string& value)
{
    // SQLITE_TRANSIENT는 sqlite가 문자열 복사본을 만들어 사용하도록 지시
    int res = sqlite3_bind_text(stmt, index, value.c_str(), value.length(), SQLITE_TRANSIENT);
    if (res != SQLITE_OK)
    {
        ELOG("Failed sqlite3_bind_text (idx {}) : {}", index, sqlite3_errmsg(_db));
        return false;
    }
    return true;
}

bool SqliteClient::bindInt(sqlite3_stmt *stmt, int index, int value)
{
    int res = sqlite3_bind_int(stmt, index, value);
    if (res != SQLITE_OK)
    {
        ELOG("Failed sqlite3_bind_int (idx {}) : {}", index, sqlite3_errmsg(_db));
        return false;
    }
    return true;
}

bool SqliteClient::executeStatement(sqlite3_stmt *stmt)
{
    std::lock_guard<std::mutex> lock(mtx);

    int res = sqlite3_step(stmt); // 실행

    // 성공이 아니면
    if (res != SQLITE_DONE)
    {
        ELOG("Failed sqlite3_step : {}", sqlite3_errmsg(_db));
        sqlite3_reset(stmt);
        return false;
    }

    // 다음 실행을 위해 함수 호출
    sqlite3_reset(stmt);
    sqlite3_clear_bindings(stmt);

    return true;
}

void SqliteClient::finalizeStatement(sqlite3_stmt *stmt)
{
    std::lock_guard<std::mutex> lock(mtx);
    
    sqlite3_finalize(stmt);
}