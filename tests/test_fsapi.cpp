#include <iostream>
#include <cstring>
extern "C" {
#include <fsapi.h>
}

class fsAPITests {
    private:

        void testOpenNewFail()
        {
            edgeos_create_file(NULL);
        }

        void testOpenNewSuccess(const char *file)
        {
            edgeos_create_file(file);
        }

        void testFileRead(const char *file)
        {
            char data[1024];
            int fd;
            int ret;

            fd = edgeos_open_file(file, "r");
            if (fd < 0)
                return;

            while (1) {
                ret = edgeos_read_file(fd, data, sizeof(data) - 1);
                if (ret <= 0)
                    break;

                //edgeos_write_file(2, data, ret);
            }

            edgeos_close_file(fd);
        }

        void testFileWrite(const char *file)
        {
            char data[] = "write something to file\n";
            int fd;
            int i;

            fd = edgeos_create_file(file);
            if (fd < 0)
                return;

            for (i = 0; i < 10000; i ++) {
                edgeos_write_file(fd, data, strlen(data));
            }

            edgeos_close_file(fd);
        }


    public:
        fsAPITests() { }
        ~fsAPITests() { }
        void testAll()
        {
            testOpenNewFail();
            testOpenNewSuccess("./t");
            testFileWrite("./t");
            testFileRead("./t");
        }
};

int fsAPI_test(int argc, char **argv)
{
    fsAPITests t;

    t.testAll();

    return 0;
}

