#include <iostream>
#include <getopt.h>
#include <cstring>
#include <stdio.h>

class EdgeOSAsn1CmdArgs {
    private:
        char *filename_;
    public:
        EdgeOSAsn1CmdArgs() { }
        ~EdgeOSAsn1CmdArgs() { }
        int parseArgs(int argc, char **argv)
        {
            int ret;

            while ((ret = getopt(argc, argv, "f:")) != -1) {
                switch (ret) {
                    case 'f':
                        filename_ = strdup(optarg);
                    break;
                    default:
                        return -1;
                }
            }

            return 0;
        }
        char *getFileName()
        {
            return filename_;
        }
};

struct EdgeOSASN1Constraints {
    std::string name;
    int satisfies;
    int optional;
    int (*scan_and_generate)(char *buf);
};

class EdgeOSAsn1Ctx {
    private:
        EdgeOSAsn1CmdArgs cmdArgs_;
        int lineOff_;
        char line_[1024];
        int first_line_;
        FILE *fp_;

        struct EdgeOSASN1Constraints *constraints;

        int parseLine();
    public:
        EdgeOSAsn1Ctx() { }
        ~EdgeOSAsn1Ctx() { }
        int initialiseEverything(int argc, char **argv);

        int parseAsn1File();

        int parseAsn1Folder();
};

int EdgeOSAsn1Ctx::parseLine()
{
    printf("line : %s\n", &line_[lineOff_]);
    return 0;
}

int EdgeOSAsn1Ctx::initialiseEverything(int argc, char **argv)
{
    int ret;

    ret = cmdArgs_.parseArgs(argc, argv);
    if (ret != 0) {
        return -1;
    }

    first_line_ = 0;

    constraints = new EdgeOSASN1Constraints[32];
    if (!constraints) {
        return -1;
    }

    return 0;
}

int EdgeOSAsn1Ctx::parseAsn1File()
{
    int ret = -1;

    fp_ = fopen(cmdArgs_.getFileName(), "r");
    if (!fp_) {
        return -1;
    }

    while (fgets(line_, sizeof(line_), fp_)) {

        line_[strlen(line_) - 1] = '\0';

        int line_len;

        line_len = strlen(line_);

        for (lineOff_ = 0; lineOff_ < line_len; lineOff_ ++) {
            if (line_[lineOff_] != ' ') {
                break;
            }
        }

        if (strlen(&line_[lineOff_]) <= 1) {
            continue;
        }

        parseLine();
    }

    return ret;
}

int EdgeOSAsn1Ctx::parseAsn1Folder()
{
    return 0;
}

int main(int argc, char **argv)
{
    EdgeOSAsn1Ctx *ctx;
    int ret;

    ctx = new EdgeOSAsn1Ctx;

    ret = ctx->initialiseEverything(argc, argv);
    if (ret != 0) {
        return -1;
    }

    ret = ctx->parseAsn1File();
    if (ret != 0) {
        return -1;
    }

    return 0;
}

