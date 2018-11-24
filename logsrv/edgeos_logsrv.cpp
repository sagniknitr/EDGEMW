#include <iostream>
#include <string>
#include <stdint.h>
#include <vector>
#include <thread>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <getopt.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <syslog.h>

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
        struct sockaddr_in serv_;
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
            logFd_ = open(filename, O_RDWR | O_CREAT, S_IRWXU);
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
    struct sockaddr_in sender;
    socklen_t sender_len;
    int rxlen;
    int ret;
    int off = 0;

    sender_len = 0;
    while (1) {
        rxlen = recvfrom(logSrv_, rxbuf_, sizeof(rxbuf_), 0,
                       (struct sockaddr *)&sender, &sender_len);
        if (ret < 0) {
            return;
        }

        
        ret = write(logFd_, rxbuf_, rxlen);
        if (ret != rxlen) {
            syslog(LOG_ERR, "logSrv: cannot write %d bytes .. written %d\n", rxlen, ret);
        }

        off += ret;

        if (off > args_.fileSize_) {
            reopenLogFile_();
            off = 0;
        }
    }
}

LogSrv::LogSrv(int argc, char **argv): logFd_(-1), logSrv_(-1)
{
    int bind_to_dev = 1;
    int ret;

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
            case 'l':
                args_.fileName_ = std::string(optarg);
            break;
            default:
                displayHelp(argv[0]);
        }
    }

    if (newLogFile_()) {
        std::cerr <<" failed to create new log file " << std::endl;
        return;
    }

    ftruncate(logFd_, args_.fileSize_ * 1024);

    logSrv_ = socket(AF_INET, SOCK_DGRAM, 0);
    if (logSrv_ < 0) {
        std::cerr << "failed to create socket" << std::endl;
        return;
    }

    serv_.sin_addr.s_addr = inet_addr(args_.ipaddr_.c_str());
    serv_.sin_port = htons(args_.port);
    serv_.sin_family = AF_INET;

    ret = setsockopt(logSrv_, SOL_SOCKET, SO_REUSEADDR, &bind_to_dev, sizeof(bind_to_dev));
    if (ret < 0) {
        std::cerr << "failed to set sock opt" << std::endl;
        close(logSrv_);
        logSrv_ = -1;
        return;
    }

    ret = bind(logSrv_, (struct sockaddr *)&serv_, sizeof(serv_));
    if (ret < 0) {
        std::cerr << "failed to bind" << std::endl;
        close(logSrv_);
        logSrv_ = -1;
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

int main(int argc, char **argv)
{
    EdgeOS::LogSrv::LogSrv service(argc, argv);

    if (service.validateClassInit()) {
        std::cerr << "failure to initialise log service " << std::endl;
        return -1;
    }

    service.Run();

    return 0;
}

