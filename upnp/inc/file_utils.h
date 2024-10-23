#ifndef FILE_UTILS_H
#define FILE_UTILS_H

#include "UpnpGlobal.h" /* for UPNP_EXPORT_SPEC */
#include <stddef.h>
#include <stdio.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifdef _WIN32
#define _fopen(fp, filepath, mode) fopen_s(&fp, filepath, mode)
#else
#define _fopen(fp, filepath, mode) fp = fopen(filepath, mode)
#endif

#define FILE_OP_ERR  0
#define FILE_OP_OK   1

/*!
 * \brief Helper macro for opening a file. Remember to fclose(file).
 *
 * \param fp returned file pointer.
 * \param filepath file path to open.
 * \param mode file opening mode.
 * \param label label to jump to in case of error.
 */
#define macro_file_open(fp, filepath, mode, label) \
{ \
    if ((filepath == NULL) || (strlen(filepath) == 0)) { \
        printf("[File Error] %s:%s(%d): Empty filepath provided.\n", \
            __FILE__, __func__, __LINE__); \
	    goto label; \
    } \
    _fopen(fp, filepath, mode); \
    if (fp == NULL) { \
        printf("[File Error] %s:%s(%d): Error opening file: %s\n", \
            __FILE__, __func__, __LINE__, filepath); \
        goto label; \
    } \
}

/*!
 * \brief Helper macro for closing a file.
 *
 * \param fp file pointer to close.
 */
#define macro_file_close(fp) \
{ \
    if (fp != NULL) { \
        fclose(fp); \
        fp = NULL; \
    } \
}

/*!
 * \brief Retrieve file size.
 *
 * \return file size.
 */
UPNP_EXPORT_SPEC size_t get_file_size(
    /*! [IN] Opened file pointer. */
    FILE* fp);

/*!
 * \brief Read file content.
 *
 * \note Remember to free the returned pointer.
 *
 * \return file content on success, NULL on failure.
 */
UPNP_EXPORT_SPEC char* read_file(
    /*! [IN] File path to read */
    const char* filepath,
    /*! [IN] file opening mode */
    const char* mode,
    /*! [OUT] read file size */
    size_t* file_size);

/*!
 * \brief Write data to file.
 *
 * \return FILE_OP_OK on success, FILE_OP_ERR on failure.
 */
UPNP_EXPORT_SPEC int write_file(
    /*! [IN] File path to write to */
    const char* filepath,
    /*! [IN] data to write */
    const unsigned char* data,
    /*! [IN] data size to write */
    size_t size);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif //FILE_UTILS_H
