#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <edgeos_logger.h>
#include <edgeos_config_parser.h>

static struct edge_os_config_parse_set *
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

    struct edge_os_config_parse_set *new_set;

    new_set = (struct edge_os_config_parse_set *)calloc(1, sizeof(struct edge_os_config_parse_set));
    if (!new_set) {
        edge_os_error("config_parser: failed to allocate @ %s %u\n",
                                __func__, __LINE__);
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

void edge_os_config_free(struct edge_os_config_parse_set *set)
{
    struct edge_os_config_parse_set *t;
    struct edge_os_config_parse_set *told;

    // silently ignore a null value
    if (!set) {
        return;
    }

    t = told = set;
    while (t) {
        told = t;
        t = t->next;
        free(told);
    }
}

struct edge_os_config_parse_set *edge_os_config_parse(const char *filename)
{
    int ret;
    int parse_count = 0;
    int line_len;
    FILE *fp;
    struct edge_os_config_parse_set *head = NULL;
    struct edge_os_config_parse_set *tail = NULL;

    if (!filename) {
        edge_os_error("config_parser: invalid filename %p @ %s %u\n",
                                    filename, __func__, __LINE__);
        return NULL;
    }

    fp = fopen(filename, "r");
    if (!fp) {
        edge_os_error("config_parser: failed to open file %s @ %s %u\n",
                                    filename, __func__, __LINE__);
        return NULL;
    }

    char config_line[1024];
    int line_count = 0;

    while (fgets(config_line, sizeof(config_line), fp)) {
        struct edge_os_config_parse_set *t;

        line_count ++;

        // remove that \n
        line_len = strlen(config_line) - 1;

        config_line[line_len] = '\0';

        t = __edge_os_parse_config_line(config_line, line_len, &ret);
        if (ret < 0) {
            edge_os_error("config_parser: failed to parse line %d @ %s %u\n",
                                    line_count, __func__, __LINE__);
            fclose(fp);
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

void edge_os_config_parser_print(struct edge_os_config_parse_set *set)
{
    struct edge_os_config_parse_set *t;

    for (t = set; t != NULL; t = t->next) {
        printf("var %s val %s\n", t->var, t->val);
    }
}

