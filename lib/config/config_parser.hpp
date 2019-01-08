#ifndef __EDGEOS_CONFIG_PARSER_HPP__
#define __EDGEOS_CONFIG_PARSER_HPP__

namespace EdgeOS {

namespace ConfigBase {

class ConfigParser {
    public:
        ConfigParser() { }
        ~ConfigParser() { }
        std::vector<std::pair<std::string, std::string> > parseConfig(std::string fileName);

    private:
};

};

};

#endif

