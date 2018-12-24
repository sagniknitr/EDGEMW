#ifndef __EOS_TOKPARSE_HPP__
#define __EOS_TOKPARSE_HPP__

#include <string>
#include <vector>

class TokParse {
    public:
        TokParse();
        std::vector<std::string> parseTokens(std::string input, char token);

        ~TokParse();
};

#endif

