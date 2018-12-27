#include <iostream>
#include <string.h>
#include <vector>
#include <string>
#include <csvclass.hpp>
#include <cstring>
#include <stdint.h>
#include <map>
#include <nmea_parser.hpp>

namespace gpslib {

inline void nmeaParser::safeInc(size_t *pos, size_t total)
{
    if ((*pos) >= total)
        std::out_of_range(std::to_string(*pos) + " is out of range ");

    (*pos) ++;
}

bool
nmeaParser::parseGGA(std::vector<std::string> &values)
{
    size_t vecSize = values.size();
    size_t pos = 1;

    memset(&GGA, 0, sizeof(GGA));

    if (values[pos].length() != 0) {
        GGA.hhmmss_sec = std::stod(values[pos]);
    }

    safeInc(&pos, vecSize);

    if (values[pos].length() != 0) {
        GGA.latitude = std::stod(values[pos]) / 100.0;
    }

    safeInc(&pos, vecSize);

    if (values[pos] == "N") {
        GGA.N = 1;
    } else if (values[pos] == "S") {
        GGA.S = 1;
    }

    safeInc(&pos, vecSize);

    if (values[pos].length() != 0) {
        GGA.longitude = std::stod(values[pos]) / 100.0;
    }

    safeInc(&pos, vecSize);

    if (values[pos] == "E") {
        GGA.E = 1;
    } else if (values[pos] == "W") {
        GGA.W = 1;
    }

    safeInc(&pos, vecSize);

    if (values[pos].length() != 0) {
        GGA.quality = static_cast<fix_quality_t>(std::stoi(values[pos]));
        if ((GGA.quality < fix_unavail) || (GGA.quality > fix_dr)) {
            return false;
        }
    }

    safeInc(&pos, vecSize);

    if (values[pos].length() != 0) {
        GGA.numSV = std::stoi(values[pos]);
    }

    safeInc(&pos, vecSize);

    if (values[pos].length() != 0) {
        GGA.hdop = std::stod(values[pos]);
    }

    safeInc(&pos, vecSize);

    if (values[pos].length() != 0) {
        GGA.antennaAltMSLMts = std::stod(values[pos]);
    }

    safeInc(&pos, vecSize);

    // skip meters unit
    safeInc(&pos, vecSize);

    if (values[pos].length() != 0) {
        GGA.geoidSeparationMts = std::stod(values[pos]);
    }

    safeInc(&pos, vecSize);

    // skip meters unit
    safeInc(&pos, vecSize);

    if (values[pos].length() != 0) {
        GGA.secsSinceLast = std::stod(values[pos]);
    }

    safeInc(&pos, vecSize);

    GGA.isValid = true;

    return true;
}

bool
nmeaParser::parseGLL(std::vector<std::string> &values)
{
    size_t vecSize = values.size();
    size_t pos = 1;

    memset(&GLL, 0, sizeof(GLL));

    if (values[pos].length() != 0) {
        GLL.latitude = std::stod(values[pos]) / 100.0;
    }

    safeInc(&pos, vecSize);

    if (values[pos] == "N") {
        GLL.N = true;
    } else if (values[pos] == "S") {
        GLL.S = true;
    }

    safeInc(&pos, vecSize);

    if (values[pos].length() != 0) {
        GLL.longitude = std::stod(values[pos]) / 100.0;
    }

    safeInc(&pos, vecSize);

    if (values[pos] == "E") {
        GLL.E = true;
    } else if (values[pos] == "W") {
        GLL.W = true;
    }

    safeInc(&pos, vecSize);

    if (values[pos].length() != 0) {
        GLL.hhmmss_sec = std::stod(values[pos]);
    }

    safeInc(&pos, vecSize);

    if (values[pos] == "A") {
        GLL.isValid = true;
    }

    return true;
}

bool
nmeaParser::parseGSA(std::vector<std::string> &values)
{
    size_t vecSize = values.size();
    size_t pos = 1;

    memset(&GSA, 0, sizeof(GSA));

    if (values[pos] == "M") {
        GSA.manual = 1;
    } else if (values[pos] == "A") {
        GSA.automatic = 1;
    }

    safeInc(&pos, vecSize);

    if (values[pos].length() != 0) {
        GSA.mode = static_cast<fix_quality_t>(std::stoi(values[pos]));
    }

    safeInc(&pos, vecSize);

    GSA.satCount = 0;

    for (auto i = pos; i < 14; i ++) {
        if (values[pos].length() != 0) {
            GSA.satIds[GSA.satCount] = std::stoi(values[pos]);
            GSA.satCount ++;
        }

        safeInc(&pos, vecSize);
    }

    if (values[pos].length() != 0) {
        GSA.pdop = std::stod(values[pos]);
    }

    safeInc(&pos, vecSize);

    if (values[pos].length() != 0) {
        GSA.hdop = std::stod(values[pos]);
    }

    safeInc(&pos, vecSize);

    if (values[pos].length() != 0) {
        GSA.vdop = std::stod(values[pos]);
    }

    safeInc(&pos, vecSize);

    GSA.isValid = 1;
    
    return true;
}

bool
nmeaParser::parseGSV(std::vector<std::string> &values)
{
    size_t vecSize = values.size();
    size_t pos = 1;
    size_t i;

    memset(&GSV, 0, sizeof(GSV));

    if (values[pos].length() != 0) {
        GSV.totalMsgs = std::stoi(values[pos]);
    }

    safeInc(&pos, vecSize);

    if (values[pos].length() != 0) {
        GSV.messageNum = std::stoi(values[pos]);
    }

    safeInc(&pos, vecSize);

    if (values[pos].length() != 0) {
        GSV.totalSvs = std::stoi(values[pos]);
    }

    safeInc(&pos, vecSize);

    // last one is CRC

    size_t svCount = vecSize - 1 - pos;

    if (svCount > sizeof(GSV.svInfo) / sizeof(GSV.svInfo[0]))
        svCount = sizeof(GSV.svInfo) / sizeof(GSV.svInfo);

    for (i = 0; (i < svCount) && (pos < vecSize); i ++) {
        if (values[pos].length() != 0) {
            GSV.svInfo[i].svPrn = std::stoi(values[pos]);
        }

        safeInc(&pos, vecSize);

        if (values[pos].length() != 0) {
            GSV.svInfo[i].elevDeg = std::stod(values[pos]);
        }

        safeInc(&pos, vecSize);

        if (values[pos].length() != 0) {
            GSV.svInfo[i].azimDegN = std::stod(values[pos]);
        }

        safeInc(&pos, vecSize);

        if (values[pos].length() != 0) {
            GSV.svInfo[i].SNR = std::stod(values[pos]);
        }

        safeInc(&pos, vecSize);
    }

    GSV.isValid = 1;

    return true;
}

bool
nmeaParser::parseRMB(std::vector<std::string> &values)
{
    size_t vecSize = values.size();
    size_t pos = 1;

    memset(&RMB, 0, sizeof(RMB));

    if (values[pos].length() != 0) {
        RMB.status = static_cast<rmb_status_t>(std::stoi(values[pos]));
    }

    safeInc(&pos, vecSize);

    if (values[pos].length() != 0) {
        RMB.crossTrackErr = std::stod(values[pos]);
    }

    safeInc(&pos, vecSize);

    if (values[pos] == "R") {
        RMB.dir = STEER_RIGHT;
    } else if (values[pos] == "L") {
        RMB.dir = STEER_LEFT;
    }

    safeInc(&pos, vecSize);

    if (values[pos].length() != 0) {
        RMB.lastWaypoint = std::stoi(values[pos]);
    }

    safeInc(&pos, vecSize);

    if (values[pos].length() != 0) {
        RMB.nextWaypoint = std::stoi(values[pos]);
    }

    safeInc(&pos, vecSize);

    if (values[pos].length() != 0) {
        RMB.latNextWaypoint = std::stod(values[pos]) / 100.0;
    }

    safeInc(&pos, vecSize);

    if (values[pos] == "N") {
        RMB.N = true;
    } else if (values[pos] == "S") {
        RMB.S = true;
    }

    safeInc(&pos, vecSize);

    if (values[pos].length() != 0) {
        RMB.longNextWaypoint = std::stod(values[pos]) / 100.0;
    }

    safeInc(&pos, vecSize);

    if (values[pos] == "E") {
        RMB.E = true;
    } else if (values[pos] == "W") {
        RMB.W = true;
    }

    safeInc(&pos, vecSize);

    if (values[pos].length() != 0) {
        RMB.rangeKnots = std::stod(values[pos]);
    }

    safeInc(&pos, vecSize);

    if (values[pos].length() != 0) {
        RMB.bearingDest = std::stod(values[pos]);
    }

    safeInc(&pos, vecSize);

    if (values[pos].length() != 0) {
        RMB.velTowardDest = std::stod(values[pos]);
    }

    safeInc(&pos, vecSize);

    if (values[pos] == "V") {
        RMB.alarm = NOT_ARRIVED;
    } else if (values[pos] == "A") {
        RMB.alarm = ARRIVED;
    }

    RMB.isValid = 1;

    return true;
}

bool
nmeaParser::parseRMC(std::vector<std::string> &values)
{
    size_t vecSize = values.size();
    size_t pos = 1;

    memset(&RMC, 0, sizeof(RMC));

    if (values[pos].length() != 0) {
        RMC.tofValid_hhmmss = std::stoi(values[pos]);
    }

    safeInc(&pos, vecSize);

    if (values[pos] == "A") {
        RMC.valid = RMC_IS_VALDID;
    } else if (values[pos] == "V") {
        RMC.valid = RMC_IS_INVALID;
    }

    safeInc(&pos, vecSize);

    if (values[pos].length() != 0) {
        RMC.latitude = std::stod(values[pos]) / 100.0;
    }

    safeInc(&pos, vecSize);

    if (values[pos] == "N") {
        RMC.N = true;
    } else if (values[pos] == "S") {
        RMC.S = true;
    }

    safeInc(&pos, vecSize);

    if (values[pos].length() != 0) {
        RMC.longitude = std::stod(values[pos]) / 100.0;
    }

    safeInc(&pos, vecSize);

    if (values[pos] == "E") {
        RMC.E = true;
    } else if (values[pos] == "W") {
        RMC.W = true;
    }

    safeInc(&pos, vecSize);

    if (values[pos].length() != 0) {
        RMC.speedKnots = std::stod(values[pos]);
    }

    safeInc(&pos, vecSize);

    if (values[pos].length() != 0) {
        RMC.trueCourse = std::stod(values[pos]);
    }

    safeInc(&pos, vecSize);

    if (values[pos].length() != 0) {
        RMC.dof_ddmmyy = std::stoi(values[pos]);
    }

    safeInc(&pos, vecSize);

    if (values[pos].length() != 0)
        RMC.magVariationDeg = std::stod(values[pos]);

    safeInc(&pos, vecSize);

    if (values[pos] == "E") {
        RMC.E = true;
    } else if (values[pos] == "W") {
        RMC.W = true;
    }

    RMC.isValid = 1;

    return true;
}

bool
nmeaParser::parseVTG(std::vector<std::string> &values)
{
    size_t vecSize = values.size();
    size_t pos = 1;

    memset(&VTG, 0, sizeof(VTG));

    if (values[pos].length() != 0) {
        VTG.trackMadeGood = std::stod(values[pos]);
    }

    safeInc(&pos, vecSize);

    // skip the tag
    safeInc(&pos, vecSize);

    // not used
    safeInc(&pos, vecSize);

    // not used
    safeInc(&pos, vecSize);

    if (values[pos].length() != 0) {
        VTG.speedOverGroundKnots = std::stod(values[pos]);
    }

    safeInc(&pos, vecSize);

    // skip the tag
    safeInc(&pos, vecSize);

    if (values[pos].length() != 0) {
        VTG.speedOverGroundKmph = std::stod(values[pos]);
    }

    safeInc(&pos, vecSize);

    // skip the tag
    safeInc(&pos, vecSize);

    VTG.isValid = 1;

    return true;
}

void dumpContents(std::vector<std::string> values)
{
    std::vector<std::string>::const_iterator it;

    std::cerr<<"dump ----------------------------" << std::endl;
    for (it = values.begin(); it != values.end(); it ++) {
        std::cerr << *it << std::endl;
    }
}

nmeaString_t nmeaParser::parseNMEA(std::string nmeaString)
{
    std::vector<std::string> values;
    csvClass csv;
    int ret;

    ret = csv.csvParse(nmeaString, values);
    if (ret <= 0) {
        return UNKNOWN;
    }

    std::vector<std::string>::reverse_iterator it;
    char lastMsg[20];

    char cksum[20];

    it = values.rbegin();

    size_t i;
    size_t j;

    memset(lastMsg, 0, sizeof(lastMsg));

    memset(cksum, 0, sizeof(cksum));

    j = 0;

    for (i = 0; i < (*it).length(); i ++) {
        if ((*it)[i] != '*')
            lastMsg[i] = (*it)[i];
        else
            break;
    }
    lastMsg[i] = '\0';

    i ++;

    for (j = 0; i < (*it).length(); i ++, j ++) {
        cksum[j] = (*it)[i];
    }

    cksum[j] = '\0';

    // FIXME: handle checksum validation
    
    values.pop_back();

    values.push_back(lastMsg);

    if (nmeaString[0] != '$') {
        return UNKNOWN;
    }

    if ((nmeaString[1] != 'G') || (nmeaString[1] == 'P')) {
        return UNKNOWN;
    }

    //dumpContents(values);

    if (nmeaString.compare(3, 3, "GGA") == 0) {
        if (!parseGGA(values))
            return UNKNOWN;

        printGGA();
        return GPGGA;
    }

    if (nmeaString.compare(3, 3, "GLL") == 0) {
        if (!parseGLL(values))
            return UNKNOWN;

        printGLL();
        return GPGLL;
    }

    if (nmeaString.compare(3, 3, "GSA") == 0) {
        if (!parseGSA(values))
            return UNKNOWN;

        printGSA();
        return GPGSA;
    }

    if (nmeaString.compare(3, 3, "GSV") == 0) {
        if (!parseGSV(values))
            return UNKNOWN;

        printGSV();
        return GPGSV;
    }

    if (nmeaString.compare(3, 3, "RMB") == 0) {
        if (!parseRMB(values))
            return UNKNOWN;

        printRMB();
        return GPRMB;
    }

    if (nmeaString.compare(3, 3, "RMC") == 0) {
        if (!parseRMC(values))
            return UNKNOWN;

        printRMC();
        return GPRMC;
    }

    if (nmeaString.compare(3, 3, "VTG") == 0) {
        if (!parseVTG(values))
            return UNKNOWN;

        printVTG();
        return GPVTG;
    }

    return UNKNOWN;
}

#ifdef CONFIG_UNIT_TESTS

void nmeaParser::printVTG()
{
    std::cerr << "VTG: {" << std::endl;
    std::cerr << "\t is Valid: " << VTG.isValid << std::endl;
    std::cerr << "\t track made Good: " << VTG.trackMadeGood << std::endl;
    std::cerr << "\t unused1: " << VTG.unused1 << std::endl;
    std::cerr << "\t unused2: " << VTG.unused2 << std::endl;
    std::cerr << "\t speed over ground knots: " << VTG.speedOverGroundKnots << std::endl;
    std::cerr << "\t speed over ground kmph: " << VTG.speedOverGroundKmph << std::endl;
    std::cerr << "}" << std::endl;
}


void nmeaParser::printGGA()
{
    std::cerr << "GGA: {" << std::endl;
    std::cerr << "\t isValid: " << GGA.isValid << std::endl;
    std::cerr << "\t hhmmss_sec: " << GGA.hhmmss_sec << std::endl;
    std::cerr << "\t latitude: " << GGA.latitude << std::endl;
    std::cerr << "\t N: " << GGA.N << std::endl;
    std::cerr << "\t S: " << GGA.S << std::endl;
    std::cerr << "\t longitude: " << GGA.longitude << std::endl;
    std::cerr << "\t E: " << GGA.E << std::endl;
    std::cerr << "\t W: " << GGA.W << std::endl;
    std::cerr << "\t quality: " << GGA.quality << std::endl;
    std::cerr << "\t numSv: " << GGA.numSV << std::endl;
    std::cerr << "\t hdop: " << GGA.hdop << std::endl;
    std::cerr << "\t antennaAltitudeMSL: " << GGA.antennaAltMSLMts << std::endl;
    std::cerr << "\t geoidSeparation: " << GGA.geoidSeparationMts << std::endl;
    std::cerr << "\t secsSinceLast: " << GGA.secsSinceLast << std::endl;
    std::cerr << "\t DGPSStationId: " << GGA.DGPSStationId << std::endl;
    std::cerr << "}" << std::endl;
}

void nmeaParser::printGLL()
{
    std::cerr << "GLL: {" << std::endl;
    std::cerr << "\t isValid: " << GLL.isValid << std::endl;
    std::cerr << "\t latitude: " << GLL.latitude << std::endl;
    std::cerr << "\t N: " << GLL.N << std::endl;
    std::cerr << "\t S: " << GLL.S << std::endl;
    std::cerr << "\t longitude: " << GLL.longitude << std::endl;
    std::cerr << "\t E: " << GLL.E << std::endl;
    std::cerr << "\t W: " << GLL.W << std::endl;
    std::cerr << "\t hhmmss_sec: " << GLL.hhmmss_sec << std::endl;
    std::cerr << "\t status: " << GLL.status << std::endl;
    std::cerr << "}" << std::endl;
}


void nmeaParser::printGSA()
{
    size_t i;

    std::cerr << "GSA: {" << std::endl;
    std::cerr << "\t isValid: " << GSA.isValid << std::endl;
    std::cerr << "\t manaul: " << GSA.manual << std::endl;
    std::cerr << "\t automatic: " << GSA.automatic << std::endl;
    std::cerr << "\t mode: " << GSA.mode << std::endl;
    std::cerr << "\t satelliteCount: " << GSA.satCount << std::endl;

    std::cerr << "\t satellites: {" << std::endl;

    for (i = 0; i < static_cast<size_t>(GSA.satCount); i ++) {
        std::cerr << "\t\t " << GSA.satIds[i] << std::endl;
    }

    std::cerr << "\t }" << std::endl;

    std::cerr << "\t pdop: " << std::endl;
    std::cerr << "\t hdop: " << std::endl;
    std::cerr << "\t vdop: " << std::endl;
    std::cerr << "}" << std::endl;
}

void nmeaParser::printGSV()
{
    size_t i;

    std::cerr << "GSV: {" << std::endl;
    std::cerr << "\t isValid: " << GSV.isValid << std::endl;
    std::cerr << "\t totalMsgs: " << GSV.totalMsgs << std::endl;
    std::cerr << "\t messgeNum: " << GSV.messageNum << std::endl;
    std::cerr << "\t totalSvs: " << GSV.totalSvs << std::endl;

    std::cerr << "\t sat Data: " << std::endl;
    for (i = 0; i < static_cast<size_t>(GSV.totalSvs); i ++) {
        std::cerr << "\t\t svPRN: " << GSV.svInfo[i].svPrn << std::endl;
        std::cerr << "\t\t elevDeg: " << GSV.svInfo[i].elevDeg << std::endl;
        std::cerr << "\t\t azimuthDegN: " << GSV.svInfo[i].azimDegN << std::endl;
        std::cerr << "\t\t SNR: " << GSV.svInfo[i].SNR << std::endl;
    }
    std::cerr << "\t }" << std::endl;
    std::cerr << "}" << std::endl;
}

void nmeaParser::printRMB()
{
    std::cerr << "RMB: {" << std::endl;
    std::cerr << "\t isValid: " << RMB.isValid << std::endl;
    std::cerr << "\t status: " << RMB.status << std::endl;
    std::cerr << "\t crossTrackErr: " << RMB.crossTrackErr << std::endl;
    std::cerr << "\t dir: " << RMB.dir << std::endl;
    std::cerr << "\t lastWaypoint: " << RMB.lastWaypoint << std::endl;
    std::cerr << "\t nextWaypoint: " << RMB.nextWaypoint << std::endl;
    std::cerr << "\t latNextWaypoint: " << RMB.latNextWaypoint << std::endl;
    std::cerr << "\t N: " << RMB.N << std::endl;
    std::cerr << "\t S: " << RMB.S << std::endl;
    std::cerr << "\t longNextWaypoint: " << RMB.longNextWaypoint << std::endl;
    std::cerr << "\t E: " << RMB.E << std::endl;
    std::cerr << "\t W: " << RMB.W << std::endl;
    std::cerr << "\t rangeKnots: " << RMB.rangeKnots << std::endl;
    std::cerr << "\t bearingDest: " << RMB.bearingDest << std::endl;
    std::cerr << "\t velTowardDest: " << RMB.velTowardDest << std::endl;
    std::cerr << "\t alarm: " << RMB.alarm << std::endl;
    std::cerr << "}" << std::endl;
}

void nmeaParser::printRMC()
{
    std::cerr << "RMC: {" << std::endl;
    std::cerr << "\t isValid: " << RMC.isValid << std::endl;
    std::cerr << "\t tofValid_hhmmss: " << RMC.tofValid_hhmmss << std::endl;
    std::cerr << "\t valid: " << RMC.valid << std::endl;
    std::cerr << "\t latitude: " << RMC.latitude << std::endl;
    std::cerr << "\t N: " << RMC.N << std::endl;
    std::cerr << "\t S: " << RMC.S << std::endl;
    std::cerr << "\t longitude: " << RMC.longitude << std::endl;
    std::cerr << "\t E: " << RMC.E << std::endl;
    std::cerr << "\t W: " << RMC.W << std::endl;
    std::cerr << "\t speedKnots: " << RMC.speedKnots << std::endl;
    std::cerr << "\t trueCourse: " << RMC.trueCourse << std::endl;
    std::cerr << "\t dof_ddmmyy: " << RMC.dof_ddmmyy << std::endl;
    std::cerr << "\t msgVariationDeg: " << RMC.magVariationDeg << std::endl;
    std::cerr << "\t mE: " << RMC.mE << std::endl;
    std::cerr << "\t mW: " << RMC.mW << std::endl;
    std::cerr << "}" << std::endl;
}

#else

void nmeaParser::printVTG()
{
}


void nmeaParser::printGGA()
{
}

void nmeaParser::printGLL()
{
}


void nmeaParser::printGSA()
{
}

void nmeaParser::printGSV()
{
}

void nmeaParser::printRMB()
{
}

void nmeaParser::printRMC()
{
}

#endif

};

