#ifndef _DBPROCESSOR_H_
#define _DBPROCESSOR_H_

#include "PacketListener.h"
#include "SqliteClient.h"

class DbProcessor : public PacketListener
{
    public:
        DbProcessor(SqliteClient *dbClient);
        virtual ~DbProcessor();

        bool initialize();

    protected:
        SqliteClient *_db;

        int current_retry_count = 0;
        const int MAX_RETRY_COUNT = 5;

        virtual void createTable() = 0;
        virtual void prepareStatements() = 0;
        virtual void finalizeStatements() = 0;

        bool tryReconnect();
};

#endif