#ifndef __CSV_CLASS_HPP__
#define __CSV_CLASS_HPP__

#include <vector>
#include <string>
extern "C" {
#include <stdio.h>
#include <stdint.h>
}

class csvClass {
    public:
        csvClass();
        ~csvClass();
        csvClass(std::string filename, std::string mode);
        int csvReadLine(std::string & line, std::vector<std::string> &output);
        int csvWriteLine(std::vector<std::string> rowInfo);
        int csvWriteLineBuf();
        void csvAppendLine(std::string line, int val, int eol);
        void csvAppendLine(int val, int eol);
        void csvAppendLine(std::string line, double val, int eol);
        void csvAppendLine(double val, int eol);
        int csvParse(std::string input, std::vector<std::string> &output);

    private:
        FILE *fp;
        std::string line_;
};

#endif

