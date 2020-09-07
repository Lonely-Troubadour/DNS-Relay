#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "dbutils.h"

#if defined(_WIN32) || defined(_WIN64)
/* The original code is public domain -- Will Hartung 4/9/09 */
/* Modifications, public domain as well, by Antti Haapala, 11/10/17
   - Switched to getc on 5/23/19 */
/** 
Srouce:

https://stackoverflow.com/questions/735126/are-there-alternate-implementations-of-gnu-getline-interface/47229318#47229318
*/
ssize_t getline(char **lineptr, size_t *n, FILE *stream);
ssize_t getline(char **lineptr, size_t *n, FILE *stream) {
    size_t pos;
    int c;

    if (lineptr == NULL || stream == NULL || n == NULL) {
        return -1;
    }

    c = getc(stream);
    if (c == EOF) {
        return -1;
    }

    if (*lineptr == NULL) {
        *lineptr = malloc(128);
        if (*lineptr == NULL) {
            return -1;
        }
        *n = 128;
    }

    pos = 0;
    while(c != EOF) {
        if (pos + 1 >= *n) {
            size_t new_size = *n + (*n >> 2);
            if (new_size < 128) {
                new_size = 128;
            }
            char *new_ptr = realloc(*lineptr, new_size);
            if (new_ptr == NULL) {
                return -1;
            }
            *n = new_size;
            *lineptr = new_ptr;
        }

        ((unsigned char *)(*lineptr))[pos ++] = c;
        if (c == '\n') {
            break;
        }
        c = getc(stream);
    }

    (*lineptr)[pos] = '\0';
    return pos;
}
#endif

/**
 * Look up name from the local dns database.
 * ________________________________________
 * Parameters:
 *     target_name: Name to look for
 *     db: Database path
 *     target_addr: Address of the target name, if exist.
 * Returns:
 *     1 if not fount, 0 if found.
 */
int lookup (char *target_name, char **db, char *target_addr) {
    FILE *fp = NULL;
    char *buf = NULL;
    char *ip_addr = NULL;
    char *name = NULL;
    int flag = 0;
    size_t len;

    /* Check database file path */
    if (*db == NULL) {
        *db = (char *) malloc(MAX_LENGTH);
        strcpy(*db, "./data/dnsrelay.txt");
        printf("--%s--\n", *db);
    }

    /* Open local database */
    fp = fopen(*db, "r");
    if (fp == NULL) {
        perror("ERROR: Load local database failed");
        exit(1);
    }
    
    /* Read lines */
    while(getline(&buf, &len, fp) != EOF) {
        ip_addr = strtok(buf, " ");
        name = strtok(NULL, " ");

        /* Remove '\n' char in the end of the string */
        name[strlen(name)-1] = '\0';

        if (strcmp(name, target_name) == 0) {
            strcpy(target_addr, ip_addr);
            flag = 1;
            break;
        }
    }

    /* Close file and clean up memory */
    if (buf) free(buf);
    fclose(fp);

    if (flag) 
        return 0;
    else
        return 1;
}
