/*
 ============================================================================
 Name        : review_siftr_log.h
 Author      : Cheng Cui
 Version     :
 Copyright   : see the LICENSE file
 Description : Check siftr log stats in C, Ansi-style
 ============================================================================
 */

#ifndef REVIEW_SIFTR2_LOG_H_
#define REVIEW_SIFTR2_LOG_H_

#include <assert.h>
#include <errno.h>
#include <getopt.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#include "lib.h"

enum line_type {
    HEAD,
    BODY,
    FOOT,
};

/* TCP traffic record fields */
enum {
    DIRECTION,      TIMESTAMP,      FLOW_ID,    CWND,   SSTHRESH,
    SNDWIN,         RCVWIN,         FLAG,       FLAG2,  STATE,
    SRTT,           RTO,            SND_BUF_HIWAT,      SND_BUF_CC,
    RCV_BUF_HIWAT,  RCV_BUF_CC,     INFLIGHT_BYTES,     REASS_QLEN,
    TH_SEQ,         TH_ACK,         TCP_DATA_SZ,
    TOTAL_FIELDS,
};

struct file_basic_stats {
    FILE        *file;
    uint64_t    num_lines;
    char        prefix[MAX_NAME_LENGTH - 20];
    double      first_flow_start_time;
};

extern bool verbose;
void stats_into_plot_file(struct file_basic_stats *f_basics, uint32_t flowid,
                          char plot_file_name[]);

void
fill_fields_from_line(char **fields, char *line, enum line_type type)
{
    int field_cnt = 0;

    // Strip newline characters at the end
    line[strcspn(line, "\r\n")] = '\0';

    // Tokenize the line using comma as the delimiter
    char *token = strtok(line, COMMA_DELIMITER);
    while (token != NULL) {
        fields[field_cnt++] = token;
        token = strtok(NULL, COMMA_DELIMITER);
    }

    if (type == BODY && field_cnt != TOTAL_FIELDS){
        printf("\nfield_cnt:%d != TOTAL_FIELDS:%d\n", field_cnt, TOTAL_FIELDS);
        PERROR_FUNCTION("field_cnt != TOTAL_FIELDS");
    }
}

int
get_file_basics(struct file_basic_stats *f_basics, const char *file_name)
{
    FILE *file = fopen(file_name, "r");
    if (!file) {
        PERROR_FUNCTION("Failed to open file");
        return EXIT_FAILURE;
    }
    f_basics->file = file;

    return EXIT_SUCCESS;
}

/* Read the body of the per-flow stats, and skip the head or foot note. */
void
read_body_by_flowid(struct file_basic_stats *f_basics, uint32_t flowid)
{
    printf("input flow id is: %08x\n", flowid);

    char plot_file_name[MAX_NAME_LENGTH];

    // Combine the strings into the plot_file buffer
    if (strlen(f_basics->prefix) == 0) {
        snprintf(plot_file_name, MAX_NAME_LENGTH, "plot_%08x.txt", flowid);
    } else {
        snprintf(plot_file_name, MAX_NAME_LENGTH, "%s.%08x.txt",
                 f_basics->prefix, flowid);
    }

    stats_into_plot_file(f_basics, flowid, plot_file_name);

    printf("input file has total lines: %" PRIu64 "\n", f_basics->num_lines);
    printf("plot_file_name: %s\n", plot_file_name);
}

int
cleanup_file_basic_stats(const struct file_basic_stats *f_basics_ptr)
{

    // Close the file and check for errors
    if (fclose(f_basics_ptr->file) == EOF) {
        PERROR_FUNCTION("Failed to close file");
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}

#endif /* REVIEW_SIFTR2_LOG_H_ */
