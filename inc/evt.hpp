namespace edgemw {

struct timerlist {
    uint32_t sec;
    uint32_t nsec;
    void (*timer_cb)(void *user_priv);
};

struct socketlist {
    int sock;
    void (*socket_cb)(void *socket_priv);
};

class evt {
    public:
        evt();
        int register_timer(uint32_t sec,
                           uint32_t nsec,
                           void (*timer_cb)(void *user_priv),
                           void *user_priv);
        int register_sock(int sock,
                          void (*socket_cb)(void *user_priv),
                          void *user_priv);
        int run();
    private:
        std::vector <struct timelist> timers;
        std::vector <struct socketlist> sockets;
        fd_set allset;
};

}
