AUTOMAKE_OPTIONS = subdir-objects

bin_PROGRAMS = ps-cpp

ps_cpp_SOURCES = \
    src/main.cpp \
    src/PacketQueueManager.cpp \
    src/CapturePkt.cpp \
    src/DbProcessor..cpp \
    src/PacketBlocker.cpp \
    src/PacketLogger.cpp \
    src/ReadConf.cpp \
    src/SqliteClient.cpp

ps_cpp_CPPFLAGS = -I$(top_srcdir)/include -Wall -g

ps_cpp_LDADD = $(PCAP_LIBS) $(SQLITE3_LIBS) $(PTHREAD_LIBS)
