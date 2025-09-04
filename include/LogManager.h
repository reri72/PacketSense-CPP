#ifndef _LOGMANAGER_H_
#define _LOGMANAGER_H_

#include <memory>
#include <string>
#include <filesystem>

#include <spdlog/spdlog.h>
#include <spdlog/sinks/rotating_file_sink.h>

#include "Singleton.h"

namespace Logger
{
    class FileLogger : public Singleton<FileLogger>
    {
        private:
            std::shared_ptr<spdlog::logger> logger_;

            // Singleton 템플릿에 접근 권한 부여
            friend class Singleton<FileLogger>;

        protected:
            FileLogger()
            {
                std::filesystem::create_directories("logs");
                logger_ = std::make_shared<spdlog::logger>(
                    "file_logger",
                    std::make_shared<spdlog::sinks::rotating_file_sink_mt>(
                        "logs/ps-cpp.log",
                        (1024 * 1024 * 5),
                        3
                    )
                );
                logger_->set_level(spdlog::level::debug);
                // 날짜 시간 파일명:라인 로그레벨 내용
                logger_->set_pattern("%Y-%m-%d %H:%M:%S : %s:%# : %l : %v");
            }

        public:
            std::shared_ptr<spdlog::logger> get_logger()
            {
                return logger_;
            }
    };
}

#define DLOG(...) \
        Logger::FileLogger::getInstance().get_logger()->log( \
        spdlog::source_loc{__FILE__, __LINE__, SPDLOG_FUNCTION}, \
        spdlog::level::debug, __VA_ARGS__)

#define ILOG(...) \
        Logger::FileLogger::getInstance().get_logger()->log( \
        spdlog::source_loc{__FILE__, __LINE__, SPDLOG_FUNCTION}, \
        spdlog::level::info, __VA_ARGS__)

#define WLOG(...) \
        Logger::FileLogger::getInstance().get_logger()->log( \
        spdlog::source_loc{__FILE__, __LINE__, SPDLOG_FUNCTION}, \
        spdlog::level::warn, __VA_ARGS__)

#define ELOG(...) \
        Logger::FileLogger::getInstance().get_logger()->log( \
        spdlog::source_loc{__FILE__, __LINE__, SPDLOG_FUNCTION}, \
        spdlog::level::err, __VA_ARGS__)

#define CLOG(...) \
        Logger::FileLogger::getInstance().get_logger()->log( \
        spdlog::source_loc{__FILE__, __LINE__, SPDLOG_FUNCTION}, \
        spdlog::level::critical, __VA_ARGS__)

#endif