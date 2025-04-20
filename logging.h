#pragma once


//#ifdef _DEBUG
//#define LOG(fmt, ...) DbgPrintEx(77, 0, \
//    "[smallzhong][%s():%u] " fmt "\n", __FUNCTION__, __LINE__, ## __VA_ARGS__)
//#else
//#define LOG(...)
//#pragma warning(disable: 4101 4189) // unreferenced local variable
//#endif


#define LOG_LEVEL_FATAL   1
#define LOG_LEVEL_ERROR   2
#define LOG_LEVEL_WARNING 3
#define LOG_LEVEL_INFO    4
#define LOG_LEVEL_DEBUG   5
#define LOG_LEVEL_TRACE   6

#define CURRENT_LOG_LEVEL LOG_LEVEL_INFO

#if CURRENT_LOG_LEVEL >= LOG_LEVEL_FATAL
#define LOG_FATAL(fmt, ...) DbgPrintEx(77, 0, "[smallzhong][%s():%u] " fmt , __FUNCTION__, __LINE__, ## __VA_ARGS__)
#define LOG_FATAL_NOPREFIX(fmt, ...) DbgPrintEx(77, 0, fmt, ## __VA_ARGS__)
#else
#define LOG_FATAL(fmt, ...)
#define LOG_FATAL_NOPREFIX(fmt, ...)
#endif

#if CURRENT_LOG_LEVEL >= LOG_LEVEL_ERROR
#define LOG_ERROR(fmt, ...) DbgPrintEx(77, 0, "[smallzhong][%s():%u] " fmt , __FUNCTION__, __LINE__, ## __VA_ARGS__)
#define LOG_ERROR_NOPREFIX(fmt, ...) DbgPrintEx(77, 0, fmt, ## __VA_ARGS__)
#else
#define LOG_ERROR(fmt, ...)
#define LOG_ERROR_NOPREFIX(fmt, ...)
#endif

#if CURRENT_LOG_LEVEL >= LOG_LEVEL_WARNING
#define LOG_WARN(fmt, ...) DbgPrintEx(77, 0, "[smallzhong][%s():%u] " fmt , __FUNCTION__, __LINE__, ## __VA_ARGS__)
#define LOG_WARN_NOPREFIX(fmt, ...) DbgPrintEx(77, 0, fmt, ## __VA_ARGS__)
#else
#define LOG_WARN(fmt, ...)
#define LOG_WARN_NOPREFIX(fmt, ...)
#endif

#if CURRENT_LOG_LEVEL >= LOG_LEVEL_INFO
#define LOG_INFO(fmt, ...) DbgPrintEx(77, 0, "[smallzhong][%s():%u] " fmt , __FUNCTION__, __LINE__, ## __VA_ARGS__)
#define LOG_INFO_NOPREFIX(fmt, ...) DbgPrintEx(77, 0, fmt, ## __VA_ARGS__)
#else
#define LOG_INFO(fmt, ...)
#define LOG_INFO_NOPREFIX(fmt, ...)
#endif

#if CURRENT_LOG_LEVEL >= LOG_LEVEL_DEBUG
#define LOG_DEBUG(fmt, ...) DbgPrintEx(77, 0, "[smallzhong][%s():%u] " fmt , __FUNCTION__, __LINE__, ## __VA_ARGS__)
#define LOG_DEBUG_NOPREFIX(fmt, ...) DbgPrintEx(77, 0, fmt, ## __VA_ARGS__)
#else
#define LOG_DEBUG(fmt, ...)
#define LOG_DEBUG_NOPREFIX(fmt, ...)
#endif

#if CURRENT_LOG_LEVEL >= LOG_LEVEL_TRACE
#define LOG_TRACE(fmt, ...) DbgPrintEx(77, 0, "[smallzhong][%s():%u] " fmt , __FUNCTION__, __LINE__, ## __VA_ARGS__)
#define LOG_TRACE_NOPREFIX(fmt, ...) DbgPrintEx(77, 0, fmt, ## __VA_ARGS__)
#else
#define LOG_TRACE(fmt, ...)
#define LOG_TRACE_NOPREFIX(fmt, ...)
#endif
