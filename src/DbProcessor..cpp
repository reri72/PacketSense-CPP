#include <iostream>

#include "DbProcessor.h"
#include "LogManager.h"

DbProcessor::DbProcessor(SqliteClient *dbClient) : _db(dbClient)
{
    //
}

DbProcessor::~DbProcessor()
{
    //
}

bool DbProcessor::initialize()
{
    if (_db && _db->isConnected())
    {
        createTable();
        prepareStatements();
        return true;
    }
    return false;
}

void DbProcessor::createTable(){}
void DbProcessor::prepareStatements(){}
void DbProcessor::finalizeStatements(){}

bool DbProcessor::tryReconnect()
{
    while (current_retry_count < MAX_RETRY_COUNT)
    {
        current_retry_count++;
        WLOG("Reconnect to DB ({}/{})", current_retry_count, MAX_RETRY_COUNT);

        if (_db->connect())
        {
            ILOG("Successfully reconnected to DB");
            
            finalizeStatements();
            createTable();
            prepareStatements();
            
            current_retry_count = 0;

            return true;
        }
        std::this_thread::sleep_for(std::chrono::seconds(1)); 
    }
    
    return false;
}
