#ifndef __EOS_FSAPI_H__
#define __EOS_FSAPI_H__

int edgeos_create_file(const char *filename);

int edgeos_create_file_truncated(const char *filename, const int filesize);

#endif

