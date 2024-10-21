#include "file_utils.h"
#include <stdlib.h>
#include "ithread.h"

#ifdef __cplusplus
extern "C" {
#endif


/**
 * \brief Internal error logging macro.
 */
#define file_error(...) { \
	fprintf(stderr, "[File Utils Error] [tid %lu] %s::%s(%d): ", \
	    ithread_self(), \
	    __FILE__, \
	    __func__, \
	    __LINE__); \
	fprintf(stderr, __VA_ARGS__); \
}

/**
 * \brief Internal message logging macro.
 */
#define file_log(...) { \
    fprintf(stdout, "[File Utils] [tid %lu] %s(%d): ", \
        ithread_self(), \
        __func__, \
        __LINE__); \
	fprintf(stdout, __VA_ARGS__); \
}

/**
 * \brief Internal verification macro.
 *
 * \param test test condition to check.
 * \param label label to jump to in case of failure.
 */
#define file_verify(test, label, ...) { \
    if (!(test)) { \
        file_error(__VA_ARGS__); \
        goto label; \
    } \
}

/**
 * \brief Free a ponter if it is not NULL.
 *
 * \param ptr pointer to free.
 */
#define file_freeif(ptr) { \
    if (ptr != NULL) { \
        free(ptr); \
        ptr = NULL; \
    } \
}

/**
 * \brief Return file size.
 *
 * \param fp file pointer.
 *
 * \return file size
 */
size_t get_file_size(FILE* fp)
{
    size_t size = 0;
    file_verify(fp != NULL, error, "File pointer is NULL\n");
    fseek(fp, 0, SEEK_END);
    size = ftell(fp);
    fseek(fp, 0, SEEK_SET);
error:
    return size;
}

char* read_file(const char* filepath, const char* mode, size_t* file_size)
{
    size_t size = 0;
    char* content = NULL;
    FILE* fp = NULL;

    // Open file
    macro_file_open(fp, filepath, mode, error);

    // Retrieve file size
    size = get_file_size(fp);
    file_verify(size > 0, error, "Error getting file size for file %s\n",
        filepath);

    // Allocate memory for file content
    content = (char*)malloc(size);
    file_verify(content != NULL, error, "Error allocating memory for file %s\n",
        filepath);

    // Verify whole file was read
    file_verify(fread(content, sizeof(char), size, fp) == size, error,
                "Error reading file %s\n", filepath);
    goto cleanup;

error:
    file_freeif(content);

cleanup:
    if (file_size != NULL)
        *file_size = size;
    macro_file_close(fp);
    return content; /* remember to free(content) */
}

int write_file(const char* filepath, const unsigned char* data,
    const size_t size)
{
    int ret = FILE_OP_ERR;
    FILE* fp = NULL;
    macro_file_open(fp, filepath, "wb", cleanup);
    file_verify(fwrite(data, sizeof(unsigned char), size, fp) == size,
        cleanup,
                "Error writing file %s\n", filepath);
    ret = FILE_OP_OK;
cleanup:
    macro_file_close(fp);
    return ret;
}


#ifdef __cplusplus
}
#endif /* __cplusplus */