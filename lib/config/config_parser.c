#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <config_parser.h>

static struct config_parse_set *
__edge_os_parse_config_line(char *config_line, int line_len, int *ret)
{
    int i;
    size_t j;

    *ret = 0;
    i = 0;

    // read past the spaces
    for (i = 0; i < line_len ; i ++) {
        if (config_line[i] != ' ')
            break;
    }

    // skip comments
    if ((config_line[i] != '\0') && (config_line[i] == '#'))
        return NULL;

    // empty line or empty spaces
    if (i >= line_len)
        return NULL;

    struct config_parse_set *new_set;

    new_set = (struct config_parse_set *)calloc(1, sizeof(struct config_parse_set));
    if (!new_set) {
        *ret = -1;
        return NULL;
    }

    size_t var_len = sizeof(new_set->var);
    size_t val_len = sizeof(new_set->val);


    for (j = 0; (i < line_len) && (j < var_len) ; i ++) {
        if (config_line[i] == '"') { // first character in the var=val item
            continue;
        }

        if ((config_line[i] != '=') && (config_line[i] != ' ')) {
            new_set->var[j] = config_line[i];
        } else {
            break;
        }
        j ++;
    }

    new_set->var[j] = '\0';
    i ++; // skip the '='

    for (; i < line_len ; i ++) {
        if (config_line[i] == '=')
            continue;
        if (config_line[i] != ' ')
            break;
    }

    for (j = 0; (i < line_len) && (j < val_len); i ++) {
        if (config_line[i] == '"') { // first character in the var=val item
            continue;
        }

        if (config_line[i] != ';') {
            new_set->val[j] = config_line[i];
        } else {
            break;
        }
        j ++;
    }

    new_set->val[j] = '\0';

    *ret = 0;
    return new_set;
}

void edge_os_config_free(struct config_parse_set *set)
{
    struct config_parse_set *t;
    struct config_parse_set *told;

    t = told = set;
    while (t) {
        told = t;
        t = t->next;
        free(told);
    }
}

struct config_parse_set *edge_os_config_parse(const char *filename)
{
    int ret;
    int parse_count = 0;
    int line_len;
    FILE *fp;
    struct config_parse_set *head = NULL;
    struct config_parse_set *tail = NULL;

    fp = fopen(filename, "r");
    if (!fp)
        return NULL;

    char config_line[1024];

    while (fgets(config_line, sizeof(config_line), fp)) {
        struct config_parse_set *t;

        // remove that \n
        line_len = strlen(config_line) - 1;

        config_line[line_len] = '\0';

        t = __edge_os_parse_config_line(config_line, line_len, &ret);
        if (ret < 0) {
            return NULL;
        }

        if (t != NULL) {
            if (!head) {
                head = t;
                tail = t;
            } else {
                tail->next = t;
                tail = t;
            }
        }

        if (ret > 0)
            parse_count ++;
    }

    fclose(fp);

    return head;
}

void edge_os_config_parser_print(struct config_parse_set *set)
{
    struct config_parse_set *t;

    for (t = set; t != NULL; t = t->next) {
        printf("var %s val %s\n", t->var, t->val);
    }
}

