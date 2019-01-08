#ifndef __EDGEOS_MASTER_LOOP_HPP__
#define __EDGEOS_MASTER_LOOP_HPP__

extern "C" {
#include <edgeos_evtloop.h>
}

class MasterLoop {
    public:
        MasterLoop()
        {
            edge_os_evtloop_init(&base_, NULL);
        }

        struct edge_os_evtloop_base *getMasterLoopBase()
        {
            return &base_;
        }

        void run()
        {
            edge_os_evtloop_run(&base_);
        }

        void cleanup()
        {
            edge_os_evtloop_deinit(&base_);
        }

    private:
        struct edge_os_evtloop_base base_;
};

#endif
