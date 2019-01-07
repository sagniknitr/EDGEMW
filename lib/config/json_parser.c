#include <stdio.h>
#include <string.h>
#include <stdlib.h>

struct edge_os_json_object {
    int new_section;
    int is_root;
    int new_array;
    int new_varval;
    char *section_name;
    char *section_val;
    char **section_array;
    struct edge_os_json_object *next;
};

int __edge_os_json_parse_file(char *line, int len)
{
    struct edge_os_json_object *obj;
    char var[1024];
    char val[1024];
    int i;

    for (i = 0; i < len; i ++) {
        if (line[i] != ' ')
            break;
    }
}

struct edge_os_json_object *edge_os_json_parse_file(const char *file)
{
    struct edge_os_json_object *obj = NULL;
    struct edge_os_json_object *end = NULL;
    FILE *fp;
    char line[1024];
    int ret;

    fp = fopen(file, "r");
    if (!fp) {
        return NULL;
    }

    fgets(line, sizeof(line), fp);

    if (line[0] != '{') {
        return NULL;
    }

    int line_count = 0;
    char var[1024];
    char val[1024];
    int i;
    int j;

    while (fgets(line, sizeof(line), fp)) {
        struct edge_os_json_object *t;

        memset(var, 0, sizeof(var));
        memset(val, 0, sizeof(val));

        t = calloc(1, sizeof(struct edge_os_json_object));
        if (!t) {
            return NULL;
        }

        line_count ++;

        int len = strlen(line) - 1;
        i = 0;
        j = 0;

        line[strlen(line) - 1] = '\0';

        if (line_count == 1) {
            if (line[i] == '{') {
                t->is_root = 1;

                goto new_obj;
            }
        }

        //printf("line: %s\n", line);
        while ((line[i] != '\0') && (line[i] == ' ')) {
            i ++;
        }

        while ((line[i] != '\0') && (line[i] != ':')) {
            var[j] = line[i];
            i ++;
            j ++;
        }
        var[j] = '\0';

        // skip the ':'
        i ++;

        //printf("var %s\n", var);
        while ((line[i] != '\0') && (line[i] == ' ')){
            i ++;
        }

        if (i < len) {
            if (line[i] == '{') {
                printf("list %s\n", &line[i]);
                t->section_name = strdup(var);
            } else if (line[i] == '[') {
                printf("array %s\n", &line[i]);
                t->new_array = 1;
                t->section_name = strdup(var);
            } else {
                char val[1024];
                size_t v = 0;

                if (var[0] != '\0') {
                    t->section_name = strdup(var);
                }

                memset(val, 0, sizeof(val));
                printf("string %s\n", &line[i]);

                while ((i < len) && (v < sizeof(val))) {
                    if (line[i] == ',') {
                        break;
                    }

                    val[v] = line[i];
                    i ++;
                    v ++;
                }
                val[v] = '\0';
                i ++;
                t->section_val = strdup(val);

                t->new_varval = 1;
            }
        }

new_obj:
        if (!obj) {
            obj = t;
            end = t;
        } else {
            end->next = t;
            end = t;
        }
    }

    struct edge_os_json_object *f;

    printf("dump f\n");
    for (f = obj; f; f = f->next) {
        if (f->section_name)
            printf("Section: %s\n", f->section_name);
        if (f->section_val)
            printf("value: %s\n", f->section_val);
    }

    fclose(fp);

    return obj;
}

int main(int argc, char **argv)
{
    edge_os_json_parse_file(argv[1]);
}

