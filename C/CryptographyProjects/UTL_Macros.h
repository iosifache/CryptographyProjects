#ifndef _UTL_MACROS_H

#define _UTL_MACROS_H

#pragma region ReturnValueChecking

// With return
#define RETURN_CHECK_RET_VAL_EQUAL(ret_val, expected_value, returned) do{ \
    if (ret_val != expected_value) \
        return returned; \
} while (0)
#define RETURN_CHECK_RET_VAL_NOT_EQUAL(ret_val, not_expected_value, returned) do{ \
    if (ret_val == not_expected_value) \
        return returned; \
} while (0)
#define RETURN_CHECK_RET_VAL_CONDITION(ret_val_condition, returned) do{ \
    if (ret_val_condition) \
        return returned; \
} while (0)

// With goto
#define GOTO_CHECK_RET_VAL_EQUAL(ret_val, expected_value, label) do{ \
    if (ret_val != expected_value) \
        goto label; \
} while (0)
#define GOTO_CHECK_RET_VAL_NOT_EQUAL(ret_val, not_expected_value, label) do{ \
    if (ret_val == not_expected_value) \
        goto label; \
} while (0)
#define GOTO_CHECK_RET_VAL_CONDITION(ret_val_condition, label) do{ \
    if (ret_val_condition) \
        goto label; \
} while (0)

#pragma endregion

#endif