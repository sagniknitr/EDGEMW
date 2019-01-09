#ifndef __EDGEOS_FSAPI_H__
#define __EDGEOS_FSAPI_H__

typedef enum {
    EDGE_OS_FILE_FULL = 1, // in cases for a limited size file
} edge_os_fsmmap_types_t;

struct edge_os_fsmmap_data {
    void *data;
    int datalen;
};

/**
 * file access mode permissions
 */
typedef enum {
    // read mode
    EDGE_OS_ACCESS_READ_OK      = 0x01,

    // write mode
    EDGE_OS_ACCESS_WRITE_OK     = 0x02,

    // exe mode
    EDGE_OS_ACCESS_EXE_OK       = 0x04,
} edge_os_access_mode_t;

/**
 * @brief - create file
 *
 * @param filename - must be valid pointer
 *
 * Description-
 *
 * create a file with given filename. If null pointer passed, the API fails
 * @returns - returns file descriptor fd and -1 on error
 */
int edgeos_create_file(const char *filename);

/**
 * @brief - create file with truncated mode (useful for creating fixed size file)
 *
 * @param filename - must be valid pointer
 * @param filesize - file size in bytes
 *
 * Description-
 *
 * create a file with given filename and truncate it. If null is passed or the filesize is
 * negative value, the API fails.
 *
 * @returns - returns file descriptor fd and -1 on error
 */
int edgeos_create_file_truncated(const char *filename, const int filesize);

/**
 * @brief - write to the file pointed by the fd
 *
 * @param fd - file descriptor (returned from os_create_file or os_open_file
 * @param msg - message pointer
 * @param msg_len - length of the message
 *
 * Description-
 *
 * write to the file pointed by fd. API never checks for msg and msg_len validity
 * for performance reasons
 *
 * @returns - returns number of bytes written on success -1 on failure
 */
int edgeos_write_file(int fd, void *msg, int msg_len);

/**
 * @brief - read file pointed by the fd
 *
 * @param fd - file descriptor (returned from os_open_file
 * @param msg - mesasge pointer
 * @param msg_len - length of the message
 *
 * Description-
 *
 * read file pointed by fd. API never checks for msg and msg_len validity
 * for performance reasons
 *
 * @returns - returns number of bytes written on success -1 on failure
 */
int edgeos_read_file(int fd, void *msg, int msg_len);

int edgeos_close_file(int fd);

int edgeos_delete_file(const char *filename);

int edgeos_write_file__safe(int fd, void *msg, int msg_len);

int edgeos_read_file__safe(int fd, void *msg, int msg_len);

int edgeos_open_file(const char *filename, const char *mode);

int edgeos_read_file__cb(const void *priv, const char *filename, void (*read_callback)(const void *ptr, void *data, int data_len));

int edgeos_get_filesize(const char *filename, size_t *file_size);

int edgeos_read_directory(void *priv, const char *dir,
                        void (*read_callback)(void *priv, const char *filename));

int edgeos_file_in_directory(const char *dir, const char *filename);

int edgeos_create_directory(const char *dir, int owner, int group, int other);

int edge_os_write_file2(const char *file, void *msg, int msg_len);

int edge_os_file_accessible(const char *file, edge_os_access_mode_t mode);

int edge_os_create_directory_recurse(const char *dir, int owner, int group, int other);

int edge_os_remove_directory(const char *dir);

int edgeos_scan_directory_recurse(const char *dir,
                                  void *priv,
                                  void (*scan_callback)(char *fullpath, int is_dir, void *priv));

void *edge_os_create_file_mmap(const char *filename, int file_size);

void *edge_os_open_file_mmap(const char *filename, int file_size);

int edge_os_write_file_mmap(void *ptr, void *bytes, int len);

int edge_os_read_file_mmap(void *ptr, struct edge_os_fsmmap_data *mmap_data);

int edge_os_close_file_mmap(void *ptr);

#endif

