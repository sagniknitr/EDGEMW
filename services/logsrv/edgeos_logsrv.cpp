#include <iostream>
#include <string>
#include <stdint.h>
#include <vector>
#include <thread>
#include <sys/time.h>
#include <time.h>
#include <getopt.h>
#include <unistd.h>
#include <syslog.h>
extern "C" {
#include <fsapi.h>
#include <edgeos_netapi.h>
}
#include <csignal>

namespace EdgeOS {

namespace LogSrv {

struct LogSrvArgs {
    std::string ipaddr_;
    int port;
    int serialise_protocol;
    std::string fileName_;
    int fileSize_;
    int logRotate_;
};

class LogSrv {
    private:
        int logFd_;
        int logSrv_;
        struct LogSrvArgs args_;
        std::thread *logRxThread_;
        void LogRxThreadF_();
        uint8_t *rxbuf_;
        void displayHelp(char *progName)
        {
            std::cout << progName << " -i <ipaddr> -p <port> "
                                  << " -s <serialise protocol> "
                                  << "-f <log file> "
                                  << std::endl;
        }
        void makeFileName_(char *filename)
        {
            struct tm t;
            time_t now = time(0);

            gmtime_r(&now, &t);
            
            sprintf(filename, "%s-%04d-%02d-%02d_%02d-%02d-%02d.txt",
                                args_.fileName_.c_str(),
                                t.tm_year + 1900,
                                t.tm_mon,
                                t.tm_mday,
                                t.tm_hour,
                                t.tm_min,
                                t.tm_sec);
        }
        int newLogFile_()
        {
            char filename[200];

            makeFileName_(filename);
            logFd_ = edgeos_create_file_truncated(filename, args_.fileSize_ * 1024 * 1024);
            if (logFd_ < 0)
                return -1;

            return 0;
        }

        int closeLogFile_()
        {
            close(logFd_);
            return 0;
        }

        int reopenLogFile_()
        {
            close(logFd_);
            return newLogFile_();
        }

    public:
        LogSrv(int argc, char **argv);
        int validateClassInit() {
            if (logFd_ < 0) {
                return -1;
            }

            if (logSrv_ < 0) {
                return -1;
            }
            
            return 0;
        }
        int Run()
        {
            rxbuf_ = new uint8_t[65535];
            if (rxbuf_ == nullptr) {
                std::cerr << "failed to allocate rxbuf" << std::endl;
                return -1;
            }

            logRxThread_ = new std::thread(&LogSrv::LogRxThreadF_, this);
            if (logRxThread_ == nullptr) {
                std::cerr << "failed to create thread" << std::endl;
                return -1;
            }

            std::cout << "log service created .. receive thread started" << std::endl;

            logRxThread_->join();

            return 0;
        }

        ~LogSrv();
};

void LogSrv::LogRxThreadF_()
{
    char dest[80];
    int dest_port = 0;
    int rxlen;
    int ret;
    int off = 0;
    int effectiveFileSize = 0;

    effectiveFileSize = args_.fileSize_ * 1024 * 1024;

    while (1) {
        rxlen = edge_os_udp_recvfrom(logSrv_, rxbuf_, 65535,
                       dest, &dest_port);
        if (rxlen < 0) {
            return;
        }

        ret = write(logFd_, rxbuf_, rxlen);
        if (ret != rxlen) {
            syslog(LOG_ERR, "logSrv: cannot write %d bytes .. written %d\n", rxlen, ret);
        }

        off += ret;

        if (off > effectiveFileSize) {
            reopenLogFile_();
            off = 0;
        }
    }
}

LogSrv::LogSrv(int argc, char **argv): logFd_(-1), logSrv_(-1)
{
    int ret;

    rxbuf_ = nullptr;

    if (argc == 1) {
        displayHelp(argv[0]);
        return;
    }

    args_.fileSize_ = 100;

    while ((ret = getopt(argc, argv, "i:p:f:s:l:S:")) != -1) {
        switch (ret) {
            case 'i':
                args_.ipaddr_ = std::string(optarg);
            break;
            case 'p':
                args_.port = std::stoi(std::string(optarg));
            break;
            case 'f':
                args_.fileName_ = std::string(optarg);
            break;
            case 's':
                args_.serialise_protocol = std::stoi(std::string(optarg));
            break;
            case 'S':
                args_.fileSize_ = std::stoi(std::string(optarg));
            break;
            default:
                displayHelp(argv[0]);
                return;
        }
    }

    if (newLogFile_()) {
        std::cerr <<" failed to create new log file " << std::endl;
        return;
    }

    logSrv_ = edge_os_create_udp_server(args_.ipaddr_.c_str(), args_.port);
    if (logSrv_ < 0) {
        std::cerr << "failed to create udp server " << args_.ipaddr_.c_str() << ":" << args_.port << std::endl;
        return;
    }
}

LogSrv::~LogSrv()
{
    delete rxbuf_;
    delete logRxThread_;
    if (logSrv_ > 0)
        close(logSrv_);
    closeLogFile_();
}

};

};

void termHandler(int signal)
{
    std::cerr << "term handle invoked" << std::endl;
    exit(0);
}

int main(int argc, char **argv)
{
    std::signal(SIGINT, termHandler);
    std::signal(SIGQUIT, termHandler);
    std::signal(SIGTERM, termHandler);

    EdgeOS::LogSrv::LogSrv service(argc, argv);

    if (service.validateClassInit()) {
        std::cerr << "failure to initialise log service " << std::endl;
        return -1;
    }

    service.Run();

    return 0;
}

