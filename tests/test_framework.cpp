#include <iostream>
#include <string>
#include <stdint.h>

extern "C" {
int prng_test(int argc, char **argv);
int list_test(int argc, char **argv);
int sysioctl_test(int argc, char **argv);
int pthread_test(int argc, char **argv);
int crypto_test(int argc, char **argv);
int sched_test(int argc, char **argv);
int dlist_test(int argc, char **argv);
int static_list_test(int argc, char **argv);
int stack_test(int argc, char **argv);
int queue_test(int argc, char **argv);
}

int config_parser_test(int argc, char **argv);
int fsAPI_test(int argc, char **argv);
int tokparse_test(int argc, char **argv);


static struct test_cases {
    std::string name;
    int (*executor)(int argc, char **argv);
} test_case[] = {
    {"list_test", list_test},
    {"prng_test", prng_test},
    {"fsapi_test", fsAPI_test},
    {"tokparse_test", tokparse_test},
    {"sysioctl_test", sysioctl_test},
    {"pthread_test", pthread_test},
    {"crypto_test", crypto_test},
    {"sched_test", sched_test},
    {"config_parser_test", config_parser_test},
    {"dlist_test", dlist_test},
    {"static_list_test", static_list_test},
    {"stack_test", stack_test},
    {"queue_test", queue_test},
};

int main(int argc, char **argv)
{
    uint32_t i;

    for (i = 0; i < sizeof(test_case) / sizeof(test_case[0]); i ++) {
        std::string exec_name =  std::string(argv[1]);

        if (exec_name == test_case[i].name) {
            test_case[i].executor(argc - 1, &argv[1]);
            break;
        }
#if 0
        if (test_case[i].executor(argc, argv)) {
            std::cerr << "test " << test_case[i].name << " failed" << std::endl;
        } else {
            std::cerr << "test " << test_case[i].name << " passed" << std::endl;
        }
#endif
    }

    return 0;
}

