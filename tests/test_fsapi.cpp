#include <iostream>
#include <cstring>
extern "C" {
#include <fsapi.h>
}


void callback_(void *priv, const char *filename)
{
    std::cerr << "file : " << filename << std::endl;
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

                ret = edgeos_read_file__safe(fd, data, sizeof(data) - 1);
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

            fd = edgeos_open_file(file, "w");
            if (fd < 0)
                return;

            for (i = 0; i < 10000; i ++) {
                edgeos_write_file(fd, data, strlen(data));
                edgeos_write_file__safe(fd, data, strlen(data));
            }

            edgeos_close_file(fd);
        }

        void testFileDelete(const char *file)
        {
            int fd;

            fd = edgeos_create_file(file);
            if (fd < 0)
                return;

            edgeos_delete_file(file);
        }

        void testFileSize(const char *file)
        {
            int ret;
            size_t size;
            int fd;

            fd = edgeos_create_file_truncated(NULL, 1);

            fd = edgeos_create_file_truncated(file, 1024 * 1024 * 2);
            if (fd < 0)
                return;

            ret = edgeos_get_filesize(NULL, &size);
            ret = edgeos_get_filesize("./string_xyz", &size);

            ret = edgeos_get_filesize(file, &size);
            if (ret < 0)
                return;

            std::cerr << "file size : " << size << std::endl;
        }

        void testReadDirectory(const char *dir, const char *file)
        {
            edgeos_read_directory(NULL, dir, callback_);

            edgeos_read_directory(NULL, NULL, callback_);

            edgeos_read_directory(NULL, NULL, NULL);

            edgeos_read_directory(NULL, "pwd", callback_);

            edgeos_file_in_directory(dir, file);

            edgeos_file_in_directory(NULL, NULL);

            edgeos_file_in_directory("pwd", file);

            edgeos_file_in_directory(dir, "pwd..file");

            edgeos_create_directory("pwd", 1, 1, 0);
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
            testFileDelete("./t");
            testFileSize("./t");
            testReadDirectory("./", "EOSTest");
        }
};

int fsAPI_test(int argc, char **argv)
{
    fsAPITests t;

    t.testAll();

    return 0;
}

