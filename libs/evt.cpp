
namespace edgemw {

evt::evt()
{
    FD_ZERO(&allset);
}

int evt::register_timer(uint32_t sec,
                        uint32_t nsec,
                        void (*timer_cb)(void *user_priv),
                        void *user_priv)
{
    return 0;
}

int evt::register_sock(int sock,
                       void (*socket_cb)(void *user_priv),
                       void *user_priv)
{
    return 0;
}

int evt::run()
{
    int ret;
    int maxfd;

    while (1) {

    }

    return 0;
}

}
