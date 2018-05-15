// opensourced NMEA parser for GPS
//
// Following are the GPS strings
//
// 1. AAM: Way point Arrival Alarm
//

struct gps_parser_ctx {
};

static void parse_gpaam(struct gps_parser_ctx *ctx)
{
}

static void parse_gpalm(struct gps_parser_ctx *ctx)
{
}

static void parse_gpapa(struct gps_parser_ctx *ctx)
{
}

static void parse_gpapb(struct gps_parser_ctx *ctx)
{
}

static void parse_gpbod(struct gps_parser_ctx *ctx)
{
}

static void parse_gpbwc(struct gps_parser_ctx *ctx)
{
}

static void parse_gpdtm(struct gps_parser_ctx *ctx)
{
}

static void parse_gpgga(struct gps_parser_ctx *ctx)
{
}

static void parse_gpgll(struct gps_parser_ctx *ctx)
{
}

static void parse_gpgrs(struct gps_parser_ctx *ctx)
{
}

static void parse_gpgsa(struct gps_parser_ctx *ctx)
{
}

static void parse_gpgst(struct gps_parser_ctx *ctx)
{
}

static void parse_gpgsv(struct gps_parser_ctx *ctx)
{
}

static void parse_gpmsk(struct gps_parser_ctx *ctx)
{
}

static void parse_gpmss(struct gps_parser_ctx *ctx)
{
}

static void parse_gpwcv(struct gps_parser_ctx *ctx)
{
}

static void parse_gpwpl(struct gps_parser_ctx *ctx)
{
}

static void parse_gpxtc(struct gps_parser_ctx *ctx)
{
}

static void parse_gpxte(struct gps_parser_ctx *ctx)
{
}

static void parse_gpzda(struct gps_parser_ctx *ctx)
{
}

static void parse_gpztg(struct gps_parser_ctx *ctx)
{
}

static void parse_gpvtg(struct gps_parser_ctx *ctx)
{
}

static void parse_gpvbw(struct gps_parser_ctx *ctx)
{
}

static void parse_gpstn(struct gps_parser_ctx *ctx)
{
}

static void parse_gptrf(struct gps_parser_ctx *ctx)
{
}

static void parse_gprte(struct gps_parser_ctx *ctx)
{
}

static void parse_gprmc(struct gps_parser_ctx *ctx)
{
}

static void parse_gprmb(struct gps_parser_ctx *ctx)
{
}

static void parse_gprma(struct gps_parser_ctx *ctx)
{
}
static const struct supported_nmea_0183_msgs {
    char *nmea_string;
    void (*nmea_parser)(struct gps_parser_ctx *gps_parser);
} parsers[] = {
    {"GPAAM", parse_gpaam},
    {"GPALM", parse_gpalm},
    {"GPAPA", parse_gpapa},
    {"GPAPB", parse_gpapb},
    {"GPBOD", parse_gpbod},
    {"GPBWC", parse_gpbwc},
    {"GPDTM", parse_gpdtm},
    {"GPGGA", parse_gpgga},
    {"GPGLL", parse_gpgll},
    {"GPGRS", parse_gpgrs},
    {"GPGSA", parse_gpgsa},
    {"GPGST", parse_gpgst},
    {"GPGSV", parse_gpgsv},
    {"GPMSK", parse_gpmsk},
    {"GPMSS", parse_gpmss},
    {"GPRMA", parse_gprma},
    {"GPRMB", parse_gprmb},
    {"GPRMC", parse_gprmc},
    {"GPRTE", parse_gprte},
    {"GPTRF", parse_gptrf},
    {"GPSTN", parse_gpstn},
    {"GPVBW", parse_gpvbw},
    {"GPVTG", parse_gpvtg},
    {"GPWCV", parse_gpwcv},
    {"GPWPL", parse_gpwpl},
    {"GPXTC", parse_gpxtc},
    {"GPXTE", parse_gpxte},
    {"GPZTG", parse_gpztg},
    {"GPZDA", parse_gpzda},
};

struct csv_data {
    char item[20];
};

int parse_input_string(char *input, struct csv_data *csv_cols)
{
    int ret;
    int col_id = 0;
    int j = 0;

    while (*input != '\0') {
        if (*input != ',') {
            csv_cols[col_id].item[j] = *input;
            j ++;
        } else {
            csv_cols[col_id].item[j] = '\0';
            col_id ++;
            j = 0;
        }
    }
    // last column handling
    csv_cols[col_id].item[j] = '\0';
    col_id ++;

    return col_id;
}

int mwos_gpsnmea_parse(char *gps_string, int gps_string_len)
{
    char *gpString;
    struct csv_data col[32];
    int n_col;

    if (gps_string[0] != '$') {
        return -1;
    }

    memset(col, 0, sizeof(col));
    n_col = parse_input_string(gps_string + 1, col);

    for (i = 0; i < sizeof(supported_nmea_0183_msgs) / sizeof(supported_nmea_0183_msgs[0]); i ++) {
        if (!strcmp(col[0].item, supported_nmea_0183_msgs[i])) {

}

