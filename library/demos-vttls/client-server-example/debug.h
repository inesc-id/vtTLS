/*
 * debug.h
 *
 *  Created on: Nov 3, 2017
 *      Author: Miguel Pardal
 */

#ifndef DEMOS_VTTLS_DEBUG_H_
#define DEMOS_VTTLS_DEBUG_H_

#include <stdio.h>

//
// Debug macros
//

// credits: https://stackoverflow.com/questions/1644868/c-define-macro-for-debug-printing

// debug flag: 0 debug off, 1 debug on
#define DEBUG 0

#define debug_print(text) \
            do { if (DEBUG) fprintf(stderr, "%s", text); } while (0)

#define debug_println(line) \
            do { if (DEBUG) fprintf(stderr, "%s\n", line); } while (0)

#define debug_printf(fmt, ...) \
            do { if (DEBUG) fprintf(stderr, fmt, __VA_ARGS__); } while (0)

// master flag: 0 trace off, 1 trace and debug on
#define TRACE 1

#define trace_print(text) \
            do { if (TRACE && DEBUG) fprintf(stderr, "%s", text); } while (0)

#define trace_println(line) \
            do { if (TRACE && DEBUG) fprintf(stderr, "%s\n", line); } while (0)

#define trace_printf(fmt, ...) \
            do { if (TRACE && DEBUG) fprintf(stderr, fmt, __VA_ARGS__); } while (0)

#endif /* DEMOS_VTTLS_DEBUG_H_ */
