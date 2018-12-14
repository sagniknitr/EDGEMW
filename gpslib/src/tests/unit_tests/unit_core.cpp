#include <iostream>
#include <stdio.h>
#include <string.h>
#include <nmea_parser.hpp>

int main(int argc, char **argv)
{
    gpslib::nmeaParser p;

    FILE *fp;

    if (argc != 2) {
        return -1;
    }

    fp = fopen(argv[1], "r");
    if (!fp) {
        return -1;
    }

    char content[1024];

    while (fgets(content, sizeof(content), fp)) {
        content[strlen(content) - 1] = '\0';

        p.parseNMEA(std::string(content));
    }

    fclose(fp);

    return 0;
}
