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
