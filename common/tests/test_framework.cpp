#include <iostream>
#include <string>
#include <stdint.h>

extern "C" {
int list_test(int argc, char **argv);
}

static struct test_cases {
    std::string name;
    int (*executor)(int argc, char **argv);
} test_case[] = {
    {"list_test", list_test}
};

int main(int argc, char **argv)
{
    uint32_t i;

    for (i = 0; i < sizeof(test_case) / sizeof(test_case[0]); i ++) {
        if (test_case[i].executor(argc, argv)) {
            std::cerr << "test " << test_case[i].name << " failed" << std::endl;
        } else {
            std::cerr << "test " << test_case[i].name << " passed" << std::endl;
        }
    }

    return 0;
}

