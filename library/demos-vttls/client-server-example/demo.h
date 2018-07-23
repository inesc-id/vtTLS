/*
 * demo.h
 *
 *  Created on: Nov 3, 2017
 *      Author: Miguel Pardal
 */

#ifndef VTTLS_DEMO_H_
#define VTTLS_DEMO_H_

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

//
// Demonstration macros
//

// Adapted from: credits: https://stackoverflow.com/questions/1644868/c-define-macro-for-debug-printing

// master switch: 1 enabled, 0 disabled
#define DEMO 1

#define demo_print(text) \
            do { if (DEMO) fprintf(stdout, "%s", text); } while (0)

#define demo_println(line) \
            do { if (DEMO) fprintf(stdout, "%s\n", line); } while (0)

#define demo_printf(fmt, ...) \
            do { if (DEMO) fprintf(stdout, fmt, __VA_ARGS__); } while (0)

#define BANNER "       _ _______ _       _____ \n" \
               "      | |__   __| |     / ____|\n" \
               "__   _| |_ | |  | |    | (___  \n" \
               "\\ \\ / / __|| |  | |     \\___ \\ \n" \
               " \\ V /| |_ | |  | |____ ____) |\n" \
               "  \\_/  \\__||_|  |______|_____/ \n"

#define demo_banner() \
	    	do { if (DEMO) demo_print(BANNER); } while (0)

// open file on graphical terminal
void demo_open_file(const char* filePath);

#endif /* VTTLS_DEMO_H_ */
