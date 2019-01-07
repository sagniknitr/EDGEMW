#include <string>
#include <vector>
extern "C" {
#include <edgeos_tokparse.h>
}
#include <TokParse.hpp>

TokParse::TokParse()
{
}

TokParse::~TokParse()
{
}

std::vector<std::string> TokParse::parseTokens(std::string input, char token)
{
    std::vector<std::string> p;
    char op[80];
    int off = 0;

    while (1) {
        off = edge_os_token_parser(input.c_str(), input.length(), token, op, sizeof(op), off);
        if (off == -1)
            break;

        p.push_back(std::string(op));
    }

    return p;
}

