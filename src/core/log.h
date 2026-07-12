#ifndef KATHTTP_LOG_H
#define KATHTTP_LOG_H

#include <cstdio>

#ifdef __ANDROID__
#include <android/log.h>
#define KATHTTP_LOG_ERR(...)                                          \
  do {                                                                \
    __android_log_print(ANDROID_LOG_ERROR, "kathttp", __VA_ARGS__);   \
  } while (0)
#define KATHTTP_LOG_WARN(...)                                         \
  do {                                                                 \
    __android_log_print(ANDROID_LOG_WARN, "kathttp", __VA_ARGS__);    \
  } while (0)
#define KATHTTP_LOG_INFO(...)                                          \
  do {                                                                 \
    __android_log_print(ANDROID_LOG_INFO, "kathttp", __VA_ARGS__);     \
  } while (0)
#define KATHTTP_LOG_DEBUG(...)                                         \
  do {                                                                 \
    __android_log_print(ANDROID_LOG_DEBUG, "kathttp", __VA_ARGS__);    \
  } while (0)
#else
#ifndef KATHTTP_LOG_LEVEL
#define KATHTTP_LOG_LEVEL 1
#endif

#define KATHTTP_LOG_ERR(...)   \
  do { if (KATHTTP_LOG_LEVEL >= 1) fprintf(stderr, "kathttp[E] " __VA_ARGS__); } while (0)
#define KATHTTP_LOG_WARN(...)  \
  do { if (KATHTTP_LOG_LEVEL >= 2) fprintf(stderr, "kathttp[W] " __VA_ARGS__); } while (0)
#define KATHTTP_LOG_INFO(...)   \
  do { if (KATHTTP_LOG_LEVEL >= 3) fprintf(stderr, "kathttp[I] " __VA_ARGS__); } while (0)
#define KATHTTP_LOG_DEBUG(...)  \
  do { if (KATHTTP_LOG_LEVEL >= 4) fprintf(stderr, "kathttp[D] " __VA_ARGS__); } while (0)
#endif

#endif /* KATHTTP_LOG_H */
