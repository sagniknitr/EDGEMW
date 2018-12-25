#include <iostream>
#include <string>
#include <cstring>
#include <vector>
#include <csvclass.hpp>

int csvClass::csvParse(std::string input, std::vector<std::string> &output)
{
    size_t i;
    int j;

    j = 0;

    char s[1024];

    for (i = 0; i != input.length(); i ++) {

        if ((input[i] != '\0') && (input[i] != ',')) {
            if (j >= 1024) {
                break;
            }
            s[j] = input[i];
            j ++;
        } else {
            s[j] = '\0';

            j = 0;

            output.push_back(std::string(s));

            memset(s, 0, sizeof(s));
        }
    }

    s[j] = '\0';
    output.push_back(std::string(s));

    return output.size();
}

csvClass::csvClass()
{
    fp = nullptr;
}

csvClass::~csvClass()
{
    if (fp)
        fclose(fp);
}

csvClass::csvClass(std::string filename, std::string mode)
{
    fp = fopen(filename.c_str(), mode.c_str());
    if (!fp) {
        return;
    }
}

int csvClass::csvReadLine(std::string & line, std::vector<std::string> &output)
{
    char inputbuf[2048];
    char *r;
    int ret;

    r = fgets(inputbuf, sizeof(inputbuf), fp);
    if (!r) {
        return 0; // EOF 
    }

    ret = csvParse(std::string(inputbuf), output);
    if (ret <= 0) {
        return -1; // empty row or invalid row
    }

    return ret;
}

int csvClass::csvWriteLine(std::vector<std::string> rowInfo)
{
    std::vector<std::string>::const_iterator it;
    std::string output;

    output.clear();

    for (it = rowInfo.begin(); it != rowInfo.end(); it ++) {
        output += *it;
    }

    fprintf(fp, "%s\n", output.c_str());

    return output.length();
}

int csvClass::csvWriteLineBuf()
{
    int len = line_.length();

    fprintf(fp, "%s\n", line_.c_str());

    line_.clear();

    return len;
}

void csvClass::csvAppendLine(std::string line, int val, int eol)
    {
    line += std::to_string(val);
    if (!eol)
        line += ',';
}

void csvClass::csvAppendLine(int val, int eol)
{
    line_ += std::to_string(val);
    if (!eol)
        line_ += ',';
}

void csvClass::csvAppendLine(std::string line, double val, int eol)
{
    line += std::to_string(val);
    if (!eol)
        line += ',';
}

void csvClass::csvAppendLine(double val, int eol)
{
    line_ += std::to_string(val);
    if (!eol)
        line_ += ',';
}

#if 0
int main()
{
    std::string input {"$GPGGA,hhmmss.ss,llll.ll,a,yyyyy.yy,a,x,xx,x.x,x.x,M,x.x,M,x.x,xxxx*hh"};
    std::vector<std::string> list;

    csvParse c(input, list);

    std::vector<std::string>::const_iterator it;

    for (it = list.begin(); it != list.end(); it ++) {
        std::cout << *it << std::endl;
    }

    list.empty();
    return 0;
}
#endif
