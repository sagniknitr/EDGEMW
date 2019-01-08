#include <iostream>
#include <string>
#include <vector>
#include <string.h>
#include <stdint.h>
#include <ubx_parser.hpp>

namespace gpslib {

size_t genericParser::parseInput(uint8_t *input, size_t offset, size_t inputLen, std::vector<parserConfig> *output)
{
    std::vector<parserConfig>::iterator it;
    size_t cur = offset;

    for (it = output->begin(); it != output->end(); it ++) {
        memcpy(it->ptr, &input[cur], it->fieldSize);
        cur += it->fieldSize;
        if (cur >= inputLen) {
            break;
        }
    }

    return cur;
}

#define NEW_PARSER_CONFIG(__pc, __fs, __ptr) { \
    __pc.fieldSize = __fs; \
    __pc.ptr = __ptr; \
};

UBXMsgType_t ubxParser::ParseUBX(uint8_t *input, size_t inputLen)
{
    std::vector<parserConfig> parseSet;
    UBXMsgType_t type = UBX_NAV_AOPSTATUS_MSG;
    size_t offset = 0;

    switch (type) {
        case UBX_NAV_AOPSTATUS_MSG: {
            parserConfig pc;

            NEW_PARSER_CONFIG(pc, 4, &aopStatus.iTOW);
            parseSet.push_back(pc);

            NEW_PARSER_CONFIG(pc, 1, &aopStatus.aopCfg);
            parseSet.push_back(pc);

            NEW_PARSER_CONFIG(pc, 1, &aopStatus.status);
            parseSet.push_back(pc);

            NEW_PARSER_CONFIG(pc, 10, &aopStatus.reserved1);
            parseSet.push_back(pc);

            p.parseInput(input, offset, inputLen, &parseSet);
        }
        break;
    }

    return type;
}

};
