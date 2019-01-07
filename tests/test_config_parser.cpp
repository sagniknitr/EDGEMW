#include <iostream>
#include <string>
#include <vector>
#include <config_parser.hpp>

int config_parser_test(int argc, char **argv)
{
    EdgeOS::ConfigBase::ConfigParser p;

    std::vector<std::pair<std::string, std::string> > v;

    printf("%s \n", argv[0]);
    v = p.parseConfig(std::string(argv[1]));
    std::vector<std::pair<std::string, std::string> >::const_iterator it;

    for (it = v.begin(); it != v.end(); it ++) {
        std::cout << "first: "
                  << (*it).first
                  << "second: "
                  << (*it).second
                  << std::endl;
    }

    return 0;

}

