#include <iostream>
#include <string>
#include <vector>
#include <functional>
#include <TcpServer.hpp>

int rxData(int fd, void *data, int dataLen)
{
    std::cerr << reinterpret_cast<char *>(data) << std::endl;

    return 0;
}

int main()
{
    MasterLoop m;

    TcpServer s(&m, std::pair<std::string, int>("127.0.0.1", 1124));

    s.registerNotifiers(&(rxData), nullptr);

    m.run();
}

