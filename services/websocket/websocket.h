#include <stdio.h>

#define frame_flag_fin      0x80
#define frame_flag_rsv1     0x40
#define frame_flag_rsv2     0x20
#define frame_flag_rsv3     0x10

#define frame_op_cont       0x00  /// continutation frame
#define frame_op_text       0x01  /// Text frame
#define frame_op_binary     0x02  /// Binart frame
#define frame_op_close
#define frame_op_ping
#define frame_op_pong 
#define frame_op_bitmask
#define frame_op_setraw

enum mode 
{
    EDGE_WS_SERVER = 1,
    EDGE_WS_CLIENT = 2
};

enum send_flags
{
    frame_text      = frame_flag_fin | frame_op_text,  // for single text
    frame_binary    = frame_flag_fin | frame_op_binary // for single binary 

};

const char* websocket_version;
static const char* edge_os_ws_guid;


enum error_codes
{
    edge_os_ws_no_handshake                       = 1,
    edge_os_ws_handshake_no_version               = 2,
    edge_os_ws_handshake_unsupported_version      = 3,
    edge_os_ws_handshake_no_accept                = 5,
    edge_os_ws_unauthorized                       = 6,
    edge_os_ws_payload_too_big                    = 10,
    edge_os_ws_incomplete_frame                   = 11

};

void edge_os_ws_init_websocket();
void edge_os_ws_shutdown_websocket();
int  edge_os_ws_send_frame();
int  edge_os_ws_receive_frame();

static struct edge_os_ws_impl edge_os_ws_accept();
static struct edge_os_ws_impl edge_os_ws_connect();
static struct edge_os_ws_impl edge_os_ws_complete_handshake();



