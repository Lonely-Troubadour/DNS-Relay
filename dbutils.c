#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "dbutils.h"

#if defined(_WIN32) || defined(_WIN64)
size_t getline(char **lineptr, size_t *n, FILE *stream);
size_t getline(char **lineptr, size_t *n, FILE *stream) {
    char *bufptr = NULL;
    char *p = bufptr;
    size_t size;
    int c;

    if (lineptr == NULL) {
        return -1;
    }
    if (stream == NULL) {
        return -1;
    }
    if (n == NULL) {
        return -1;
    }
    bufptr = *lineptr;
    size = *n;

    c = fgetc(stream);
    if (c == EOF) {
        return -1;
    }
    if (bufptr == NULL) {
        bufptr = malloc(128);
        if (bufptr == NULL) {
            return -1;
        }
        size = 128;
    }
    p = bufptr;
    while(c != EOF) {
        if ((p - bufptr) > (size - 1)) {
            size = size + 128;
            bufptr = realloc(bufptr, size);
            if (bufptr == NULL) {
                return -1;
            }
        }
        *p++ = c;
        if (c == '\n') {
            break;
        }
        c = fgetc(stream);
    }

    *p++ = '\0';
    *lineptr = bufptr;
    *n = size;

    return p - bufptr - 1;
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
int lookup (char *target_name, char *db, char *target_addr) {
    FILE *fp = NULL;
    char *buf = NULL;
    char *ip_addr = NULL;
    char *name = NULL;
    int flag = 0;
    size_t len;

    /* Open local database */
    if (db == NULL) {
        db = (char *) malloc(MAX_LENGTH);
        strcpy(db, "./data/dnsrelay.txt");
    }

    fp = fopen(db, "r");
    if (fp == NULL) {
        perror("ERROR: Load local database failed.");
        exit(1);
    }
    
    /* Read lines */
    while(getline(&buf, &len, fp) != EOF) {
        ip_addr = strtok(buf, " ");
        name = strtok(NULL, " ");

        /* Remove '\n' char in the end of the string */
        name[strlen(name)-1] = '\0';

        // printf("%s %s %s\n", name, ip_addr, target_name);

        if (strcmp(name, target_name) == 0) {
            strcpy(target_addr, ip_addr);
            flag = 1;
            break;
        }
    }

    /* Close file and clean up memory */
    if (buf) free(buf);
    if (db) free(db);
    fclose(fp);

    if (flag) 
        return 0;
    else
        return 1;
}
