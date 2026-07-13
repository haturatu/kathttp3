#ifndef KATHTTP3_LOG_H
#define KATHTTP3_LOG_H

#include <cstdio>

#ifdef __ANDROID__
#include <android/log.h>
#define KATHTTP3_LOG_ERR(...)                                            \
    do {                                                                 \
        __android_log_print(ANDROID_LOG_ERROR, "kathttp3", __VA_ARGS__); \
    } while (0)
#define KATHTTP3_LOG_WARN(...)                                          \
    do {                                                                \
        __android_log_print(ANDROID_LOG_WARN, "kathttp3", __VA_ARGS__); \
    } while (0)
#define KATHTTP3_LOG_INFO(...)                                          \
    do {                                                                \
        __android_log_print(ANDROID_LOG_INFO, "kathttp3", __VA_ARGS__); \
    } while (0)
#define KATHTTP3_LOG_DEBUG(...)                                          \
    do {                                                                 \
        __android_log_print(ANDROID_LOG_DEBUG, "kathttp3", __VA_ARGS__); \
    } while (0)
#else
#ifndef KATHTTP3_LOG_LEVEL
#define KATHTTP3_LOG_LEVEL 1
#endif

#define KATHTTP3_LOG_ERR(...)                                                     \
    do {                                                                          \
        if (KATHTTP3_LOG_LEVEL >= 1) fprintf(stderr, "kathttp3[E] " __VA_ARGS__); \
    } while (0)
#define KATHTTP3_LOG_WARN(...)                                                    \
    do {                                                                          \
        if (KATHTTP3_LOG_LEVEL >= 2) fprintf(stderr, "kathttp3[W] " __VA_ARGS__); \
    } while (0)
#define KATHTTP3_LOG_INFO(...)                                                    \
    do {                                                                          \
        if (KATHTTP3_LOG_LEVEL >= 3) fprintf(stderr, "kathttp3[I] " __VA_ARGS__); \
    } while (0)
#define KATHTTP3_LOG_DEBUG(...)                                                   \
    do {                                                                          \
        if (KATHTTP3_LOG_LEVEL >= 4) fprintf(stderr, "kathttp3[D] " __VA_ARGS__); \
    } while (0)
#endif

#endif /* KATHTTP3_LOG_H */
