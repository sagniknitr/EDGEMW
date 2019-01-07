#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <edgeos_logger.h>

struct edge_os_ini_section_data {
    char variable[256];
    char value[256];
    struct edge_os_ini_section_data *next;
};

struct edge_os_ini_set {
    char section_name[40];
    int valid_section;
    struct edge_os_ini_section_data *sec_data;
    struct edge_os_ini_section_data *sec_last;
    struct edge_os_ini_set *next;
};

static int __edge_os_ini_parse_var_val(char *input, int off, char *var, char *val)
{
    uint32_t i;
    uint32_t j;
    int input_len = strlen(input);

    i = j = off;

    while (input[i] != '\0') {
        if (input[i] == '=') {
            break;
        }
        var[j] = input[i];
        i ++;
        j ++;
    }

    var[j] = '\0';
    i ++;

    j = 0;
    while (input[i] != '\0') {
        val[j] = input[i];
        i ++;
        j ++;
    }

    val[j] = '\0';

    printf("var %s val %s\n", var, val);
}

static int __edge_os_add_sec_data_to_set(struct edge_os_ini_set *set,
                                         struct edge_os_ini_section_data *sec_data)
{
    if (!set->sec_data) {
        set->sec_data = sec_data;
        set->sec_last = sec_data;
    } else {
        set->sec_last->next = sec_data;
        set->sec_last = NULL;
    }

    return 0;
}

struct edge_os_ini_set *edge_os_ini_parse_file(const char *ini)
{
    FILE *fp;
    struct edge_os_ini_set *master = NULL;
    struct edge_os_ini_set *next = NULL;
    struct edge_os_ini_section_data *sec_next = NULL;

    if (!ini) {
        return NULL;
    }

    fp = fopen(ini, "r");
    if (!fp) {
        return NULL;
    }

    char input[1024];
    uint32_t i;

    struct edge_os_ini_set set;

    memset(&set, 0, sizeof(set));

    while (fgets(input, sizeof(input), fp)) {
        char section[40];
        uint32_t j;

        input[strlen(input) - 1] = '\0';

        i = 0;

        // skip spaces
        while (input[i] == ' ') {
            i ++;
        }

        // skip comment
        if (input[i] == '#') {
            continue;
        }

        if (input[i] == '[') {
            j = 0;

            while ((input[i] != ']') || (input[i] != '\0')) {
                if (j >= sizeof(section)) {
                    break;
                }

                section[j] = input[i];
                i ++;
                j ++;
            }

            section[j] = '\0';

            if (!set.valid_section) {
                strcpy(set.section_name, section);
                set.valid_section = 1;
            } else {
                if (!master) {
                    master = calloc(1, sizeof(struct edge_os_ini_set));
                    if (!master) {
                        return NULL;
                    }
                }
                next = master;

                strcpy(next->section_name, set.section_name);
                next->valid_section = 1;
                master->sec_data = set.sec_data;
            }
        } else if (i < strlen(input)) {
            struct edge_os_ini_section_data *sec_data;

            if (!set.valid_section)
                continue;

            sec_data = calloc(1, sizeof(struct edge_os_ini_section_data));
            if (!sec_data) {
                return NULL;
            }

            __edge_os_ini_parse_var_val(input, i, sec_data->variable, sec_data->value);

            if (!set.sec_data) {
                set.sec_data = sec_data;
                set.sec_last = sec_data;
            } else {
                set.sec_last->next = sec_data;
                set.sec_last = sec_data;
            }
        }
    }

    fclose(fp);
    return master;
}


int main(int argc, char **argv)
{
    if (argc != 2) {
        return -1;
    }

    edge_os_ini_parse_file(argv[1]);
}

