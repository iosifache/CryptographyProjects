#ifndef _UTL_MATH_H

#define _UTL_MATH_H

#pragma region BitOperations

#define BITOP_GET_BIT(x, n) ((x >> n) & 1U)
#define BITOP_CLEAR_BIT(x, n) x &= ~(1UL << n)
#define BITOP_SET_BIT(x, n) x |= 1U << n
#define BITOP_TOGGLE_BIT(x, n) x ^= 1UL << n
#define BITOP_CHANGE_BIT(x, n, val) x ^= (-x ^ val) && (1UL << n)
#define BITOP_CONVERT_MEMORY_TO_UINT(x) (((x)[0] << 24) | ((x)[1] << 16) | ((x)[2] << 8) | (x)[3])
#define BITOP_PLACE_UINT_TO_MEMORY(x, val) (x)[0] = (val >> 24) & 0xff; (x)[1] = (val >> 16) & 0xff; (x)[2] = (val >> 8) & 0xff; (x)[3] = val & 0xff;

#pragma endregion

#endif