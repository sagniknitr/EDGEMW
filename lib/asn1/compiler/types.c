#include <stdio.h>
#include <string.h>

typedef enum {
    EDGEOS_ASN1_TYPE_INT,
    EDGEOS_ASN1_TYPE_UINT,
    EDGEOS_ASN1_TYPE_HEX_STRING,
    EDGEOS_ASN1_TYPE_DOUBLE,
    EDGEOS_ASN1_TYPE_ENUM,
    EDGEOS_ASN1_TYPE_INT64,
    EDGEOS_ASN1_TYPE_UINT64,
    EDGEOS_ASN1_TYPE_STRING,
    EDGEOS_ASN1_TYPE_DATE,
    EDGEOS_ASN1_TYPE_STRUCT,
    EDGEOS_ASN1_TYPE_ARRAY,
    EDGEOS_ASN1_TYPE_UNION,
} edgeos_asn1_c_type_t;
static struct edgeos_asn1_types {
    char *typename;
    char *c_type;
    edgeos_asn1_c_type_t type;
    char *c_min_range;
    char *c_max_range;
    int implemented;
    int (*impl_callback)(char *input, struct edgeos_asn1_types *type_data);
} recognised_types[] = {
    {"BOOLEAN", "int", EDGEOS_ASN1_TYPE_INT, "0", "1", 0, NULL},
    {"INTEGER", "int", EDGEOS_ASN1_TYPE_INT, "-2147483648", "2147483647", 0, NULL},
    {"BIT STRING", "uint32", EDGEOS_ASN1_TYPE_UINT, "0", "0", 0, NULL},
    {"OCTET STRING", "uint8 *", EDGEOS_ASN1_TYPE_HEX_STRING, NULL, NULL, 0, NULL},
    {"DATE", "date", EDGEOS_ASN1_TYPE_DATE, NULL, NULL, 0, NULL},
    {"REAL", "double", EDGEOS_ASN1_TYPE_DOUBLE, NULL, NULL, 0, NULL},
    {"ENUMERATED", "enum", EDGEOS_ASN1_TYPE_ENUM, NULL, NULL, 0, NULL},
    {"SEQUENCE", "struct", EDGEOS_ASN1_TYPE_STRUCT, NULL, NULL, 0, NULL},
    {"SEQUENCE OF", "array", EDGEOS_ASN1_TYPE_ARRAY, NULL, NULL, 0, NULL},
    {"CHOICE", "union", EDGEOS_ASN1_TYPE_UNION, NULL, NULL, 0, NULL},
    {"IA5String", "string", EDGEOS_ASN1_TYPE_STRING, NULL, NULL, 0, NULL},
    {"VisibleString", "string", EDGEOS_ASN1_TYPE_STRING, NULL, NULL, 0, NULL},
    {"NumericString", "string", EDGEOS_ASN1_TYPE_STRING, NULL, NULL, 0, NULL},
};

int edgeos_asn1_type_system_initialise()
{
    return 0;
}

int edgeos_asn1_has_type_support(char *input)
{
    size_t i;

    for (i = 0; i < sizeof(recognised_types) / sizeof(recognised_types[0]); i ++) {
        if (strstr(input, recognised_types[i].typename))
            return 1;
    }

    return 0;
}

