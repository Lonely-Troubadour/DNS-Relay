/**
 * This file is the header file for database utils, that provides some 
 * useful utils for database related functions.
 * -----------------------------------------------------------------------------
 * The header file includes dnsutils header file. Specifically, it is for the 
 * define of max string length.
 * 
 * Some important functions are defined here.
 *     lookup: Open the local database and look up the name.
 * 
 * The header file includes different system header files based on different OS.
 * -----------------------------------------------------------------------------
 * Authors: Yongjian Hu, Zhihao Song, Yutong Si
 * License: GPLv3
 * Date: 15-07-2020
 */
#ifndef _DBUTILS_H_
#define _DBUTILS_H_

#include "dnsutils.h"
#include "utils.h"

#endif
int lookup (char *target_name, char **db, char *target_addr);
