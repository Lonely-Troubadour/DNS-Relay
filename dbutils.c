#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "dbutils.h"

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
