#include <iostream>
#include <TokParse.hpp>
#include <csvparse.hpp>

void printVector(std::vector<std::string> s)
{
    std::vector<std::string>::const_iterator it;

    for (it = s.begin(); it != s.end(); it ++) {
        std::cerr << *it << std::endl;
    }
}

int main()
{
    std::string b = "/home/dev/test1/test2/test3/test4/test5/";
    std::string c = "/home,dev,test1,test2,test3,test4,test5";
    TokParse s;

    std::vector<std::string> r = s.parseTokens(b, '/');
    printVector(r);

    r = s.parseTokens(c, ',');
    printVector(r);

    r = s.parseTokens(c, ';');
    printVector(r);

    csvParse c_(c, r);
    printVector(r);
}

