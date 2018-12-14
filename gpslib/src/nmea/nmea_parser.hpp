#ifndef __NMEA_PARSER_H__
#define __NMEA_PARSER_H__

#include <vector>
#include <string>

namespace gpslib {

#define NMEA_SIZE_OF(__var) ((sizeof(__var)) / (sizeof(__var[0])))

typedef enum {
    fix_unavail = 0,
    fix_1d_gps,
    fix_2d_gps,
    fix_dr,
} fix_quality_t;


typedef enum {
    GPGGA = 1,
    GPGLL = 2,
    GPGSA = 3,
    GPGSV = 4,
    GPRMB = 5,
    GPRMC = 6,
    GPVTG = 7,
    UNKNOWN = 255,
} nmeaString_t;

struct nmeaSentenceGGA {
    bool isValid;
    double hhmmss_sec;
    double latitude;
    bool N;
    bool S;
    double longitude;
    bool E;
    bool W;
    fix_quality_t quality;
    int numSV;
    double hdop;
    double antennaAltMSLMts;
    double geoidSeparationMts;
    double secsSinceLast; // age of data
    int DGPSStationId;
};

struct nmeaSentenceGLL {
    bool isValid;
    double latitude;
    bool N;
    bool S;
    double longitude;
    bool E;
    bool W;
    double hhmmss_sec;
    char status;
};

struct nmeaSentenceGSA {
    bool isValid;
    bool manual;
    bool automatic;
    fix_quality_t mode;
    int satCount;
    int satIds[20];
    double pdop;
    double hdop;
    double vdop;
};

struct nmeaSentenceGSV {
    bool isValid;
    int totalMsgs;
    int messageNum;
    int totalSvs;
    struct nmeaSVInfo {
        int svPrn;
        double elevDeg;
        double azimDegN;
        double SNR;
    } svInfo[20];
};

typedef enum {
    RMB_STATUS_OK,
    RMB_STATUS_WARN,
} rmb_status_t;

typedef enum {
    STEER_RIGHT,
    STEER_LEFT,
} steer_status_t;

typedef enum {
    ARRIVED,
    NOT_ARRIVED,
} arival_alarm_t;

struct nmeaSentenceRMB {
    bool isValid;
    rmb_status_t status;
    double crossTrackErr;
    steer_status_t dir;
    int lastWaypoint;
    int nextWaypoint;
    double latNextWaypoint;
    bool N;
    bool S;
    double longNextWaypoint;
    bool E;
    bool W;
    double rangeKnots;
    double bearingDest;
    double velTowardDest;
    arival_alarm_t alarm;
};

typedef enum {
    RMC_IS_VALDID,
    RMC_IS_INVALID,
} rmc_valid_t;

struct nmeaSentenceRMC {
    bool isValid;
    double tofValid_hhmmss;
    rmc_valid_t valid;
    double latitude;
    bool N;
    bool S;
    double longitude;
    bool E;
    bool W;
    double speedKnots;
    double trueCourse;
    double dof_ddmmyy;
    double magVariationDeg;
    bool mE;
    bool mW;
};


struct nmeaSentenceVTG {
    bool isValid;
    double trackMadeGood;
    int unused1;
    int unused2;
    double speedOverGroundKnots;
    double speedOverGroundKmph;
};

class nmeaParser {
    public:
        nmeaParser()
        {
            memset(&GGA, 0, sizeof(GGA));
            memset(&GLL, 0, sizeof(GLL));
            memset(&GSA, 0, sizeof(GSA));
            memset(&GSV, 0, sizeof(GSV));
            memset(&RMB, 0, sizeof(RMB));
            memset(&RMC, 0, sizeof(RMC));
            memset(&VTG, 0, sizeof(VTG));
        };
        ~nmeaParser() {};

        nmeaString_t parseNMEA(std::string nmeaString);
        nmeaSentenceGGA *getGGA() {
            return &GGA;
        }
        nmeaSentenceGLL *getGLL() {
            return &GLL;
        }
        nmeaSentenceGSA *getGSA() {
            return &GSA;
        }
        nmeaSentenceGSV *getGSV() {
            return &GSV;
        }
        nmeaSentenceRMB *getRMB() {
            return &RMB;
        }
        nmeaSentenceRMC *getRMC() {
            return &RMC;
        }
        nmeaSentenceVTG *getVTG() {
            return &VTG;
        }

        void printRMC();
        void printRMB();
        void printGSV();
        void printGSA();
        void printGLL();
        void printGGA();
        void printVTG();
    private:
        struct nmeaSentenceGGA GGA;

        struct nmeaSentenceGLL GLL;

        struct nmeaSentenceGSA GSA;

        struct nmeaSentenceGSV GSV;

        struct nmeaSentenceRMB RMB;

        struct nmeaSentenceRMC RMC;

        struct nmeaSentenceVTG VTG;

        bool parseGGA(std::vector<std::string> &values, size_t offset);

        bool parseGLL(std::vector<std::string> &values, size_t offset);

        bool parseGSA(std::vector<std::string> &values, size_t offset);

        bool parseGSV(std::vector<std::string> &values, size_t offset);

        bool parseRMB(std::vector<std::string> &values, size_t offset);

        bool parseRMC(std::vector<std::string> &values, size_t offset);

        bool parseVTG(std::vector<std::string> &values, size_t offset);

        inline void safeInc(size_t *pos, size_t total);
};

};


#endif

