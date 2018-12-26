#include <iostream>
#include <TokParse.hpp>
#include <csvclass.hpp>

void printVector(std::vector<std::string> s)
{
    std::vector<std::string>::const_iterator it;

    for (it = s.begin(); it != s.end(); it ++) {
        std::cerr << *it << std::endl;
    }
}

int tokparse_test(int argc, char **argv)
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

    csvClass c_;

    c_.csvParse(c, r);
    printVector(r);

    return 0;
}

