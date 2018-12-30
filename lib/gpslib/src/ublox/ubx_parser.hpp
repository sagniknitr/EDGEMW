#ifndef __UBX_PARSER_H__
#define __UBX_PARSER_H__

#include <iostream>
#include <string.h>
#include <vector>
#include <string>
#include <stdint.h>

namespace gpslib {

typedef enum {
    UBX_NAV_AOPSTATUS_MSG,
} UBXMsgType_t;

typedef enum {
    UBX_CLS_NAV = 0x01,
    UBX_CLS_RXM = 0x02,
    UBX_CLS_INF = 0x04,
    UBX_CLS_ACK = 0x05,
    UBX_CLS_CFG = 0x06,
    UBX_CLS_UPD = 0x09,
    UBX_CLS_MON = 0x0A,
    UBX_CLS_AID = 0x0B,
    UBX_CLS_TIM = 0x0D,
    UBX_CLS_ESF = 0x10,
    UBX_CLS_MGA = 0x13,
    UBX_CLS_LOG = 0x21,
    UBX_CLS_SEC = 0x27,
    UBX_CLS_HNR = 0x28,
} UBXClasses_t;

typedef enum {
    UBX_AOP_USE_AOP = 0x01,
} UBX_AOP_CFG_BITS_t;

struct UBX_NAV_AOPSTATUS {
    uint32_t iTOW;
    uint8_t aopCfg;
    uint8_t status;
    uint8_t reserved1[10];
};

typedef enum {
    FIELD_TYPE_UINT8,
    FIELD_TYPE_INT8,
    FIELD_TYPE_UINT16,
    FIELD_TYPE_INT16,
    FIELD_TYPE_UINT32,
    FIELD_TYPE_INT32,
    FIELD_TYPE_BYTE_STREAM,
} fieldType_t;

struct parserConfig {
    uint8_t fieldSize;
    void *ptr;
};

class genericParser {
    public:
        genericParser() { }
        ~genericParser() { }
        size_t parseInput(uint8_t *input, size_t offset, size_t inputLen, std::vector<parserConfig> *output);
};

class ubxParser {
    public:
        ubxParser() { }
        ~ubxParser() { }

        UBXMsgType_t ParseUBX(uint8_t *input, size_t inputLen);

        UBX_NAV_AOPSTATUS *getAOP_STATUS() {
            return &aopStatus;
        }

    private:
        genericParser p;
        struct UBX_NAV_AOPSTATUS aopStatus;
};

}

#endif

