#include <iostream>
#include <config_parser.h>
#include <string>
#include <vector>
#include <config_parser.hpp>

namespace EdgeOS {

namespace ConfigBase {

std::vector<std::pair<std::string, std::string> > ConfigParser::parseConfig(std::string fileName)
{
    struct edge_os_config_parse_set *set;
    std::vector<std::pair<std::string, std::string> > parseData;

    parseData.empty();

    set = edge_os_config_parse(fileName.c_str());
    if (!set) {
        return parseData;
    }

    struct edge_os_config_parse_set *set_it;

    for (set_it = set; set_it != NULL; set_it = set_it->next) {
        std::pair<std::string, std::string> item;

        item.first = std::string(set_it->var);
        item.second = std::string(set_it->val);

        parseData.push_back(item);
    }

    edge_os_config_free(set);
    return parseData;
}

};

};

#if 0
int main(int argc, char **argv)
{
    std::vector<std::pair<std::string, std::string> > parseData;
    std::vector<std::pair<std::string, std::string> >::const_iterator cit;
    EdgeOS::ConfigBase::ConfigParser p;

    parseData = p.parseConfig(std::string(argv[1]));

    for (cit = parseData.begin(); cit != parseData.end(); cit ++) {
        std::cerr << "var : " << cit->first << "val : " << cit->second << std::endl;
    }
}

#endif

