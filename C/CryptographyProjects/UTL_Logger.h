#ifndef _UTL_LOGGER_H

#define _UTL_LOGGER_H

#pragma region IncludedHeaders

#include <stdio.h>

#pragma endregion

#pragma region Defines

// Available colors
#define COLOR_RED 31
#define COLOR_GREEN 32
#define COLOR_YELLOW 33
#define COLOR_BLUE 34
#define COLOR_WHITE 37

#pragma endregion

#pragma region Macros

// Colord print macro
#define COLORED_LOG(color_code, format, ...) printf("\033[%dm[+] " format "\n\033[0m", color_code, ##__VA_ARGS__)

// Macro for checking return value
#define RETURN_LOGGER_CHECK_RET_VAL_EQUAL(ret_val, expected_value, operation_description, returned) do{ \
    if (ret_val != expected_value){ \
        COLORED_LOG(COLOR_RED, "Error on %s", operation_description); \
        return returned; \
    } \
    else \
        COLORED_LOG(COLOR_GREEN, "Success on %s", operation_description); \
} while (0)
#define RETURN_LOGGER_CHECK_RET_VAL_NOT_EQUAL(ret_val, not_expected_value, operation_description, returned) do{ \
    if (ret_val == not_expected_value){ \
        COLORED_LOG(COLOR_RED, "Error on %s", operation_description); \
        return returned; \
    } \
    else \
        COLORED_LOG(COLOR_GREEN, "Success on %s", operation_description); \
} while (0)
#define GOTO_LOGGER_CHECK_RET_VAL_EQUAL(ret_val, expected_value, operation_description, label) do{ \
    if (ret_val != expected_value){ \
        COLORED_LOG(COLOR_RED, "Error on %s", operation_description); \
        goto label; \
    } \
    else \
        COLORED_LOG(COLOR_GREEN, "Success on %s", operation_description); \
} while (0)
#define GOTO_LOGGER_CHECK_RET_VAL_NOT_EQUAL(ret_val, not_expected_value, operation_description, label) do{ \
    if (ret_val == not_expected_value){ \
        COLORED_LOG(COLOR_RED, "Error on %s", operation_description); \
         goto label; \
    } \
    else \
        COLORED_LOG(COLOR_GREEN, "Success on %s", operation_description); \
} while (0)

#pragma endregion

#endif