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
#include <unistd.h>

#include "lib.h"

enum line_type {
    HEAD,
    BODY,
    FOOT,
};
enum {
    ENABLE_TIME_SECS,
    ENABLE_TIME_USECS,
    SIFTRVER,
    SYSNAME,
    SYSVER,
    IPMODE,
    TOTAL_FIRST_LINE_FIELDS,
};

enum {
    DISABLE_TIME_SECS,
    DISABLE_TIME_USECS,
    GLOBAL_FLOW_CNT,
    MAX_TMP_QSIZE,
    AVG_TMP_QSIZE,
    MAX_STR_SIZE,
    ALQ_GETN_FAIL_CNT,
    GEN_FLOWID_CNT,
    FLOW_LIST,
    TOTAL_LAST_LINE_FIELDS,
};

struct last_line_fields {
    uint32_t    global_flow_cnt;
    uint32_t    max_tmp_qsize;
    uint32_t    avg_tmp_qsize;
    uint32_t    max_str_size;
    uint32_t    alq_getn_fail_cnt;
    uint32_t    gen_flowid_cnt;
    uint32_t    line_len;           /* includes the null terminator */
    char        *flow_list_str;
    struct timeval disable_time;
};

/* flow list fields in the foot note of the siftr2 log */
enum {
    FL_FLOW_ID,     FL_LOIP,        FL_LPORT,       FL_FOIP,    FL_FPORT,
    FL_STACK_TYPE,  FL_TCP_CC,      FL_MSS,         FL_ISSACK,  FL_SNDSCALE,
    FL_RCVSCALE,    FL_NUMRECORD,   FL_NTRANS,      TOTAL_FLOWLIST_FIELDS,
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

struct flow_info {
    /* permanent info */
    uint32_t    flowid;                     /* flowid of the connection */
    char        laddr[INET6_ADDRSTRLEN];    /* local IP address */
    char        faddr[INET6_ADDRSTRLEN];    /* foreign IP address */
    uint16_t    lport;                      /* local TCP port */
    uint16_t    fport;                      /* foreign TCP port */
    uint8_t     ipver;                      /* IP version */
    /* infrequently change info */
    enum {
        FBSD = 0,
        RACK = 1,
    }           stack_type;                 /* net stack name: freebsd or rack */
    enum {
        CUBIC = 0,
        NEWRENO = 1,
    }           tcp_cc;                     /* TCP congestion control name */
    uint32_t    mss;
    bool        isSACK;
    uint8_t     snd_scale;                  /* Window scaling for snd window. */
    uint8_t     rcv_scale;                  /* Window scaling for recv window. */
    uint32_t    record_cnt;
    uint32_t    trans_cnt;
    uint32_t    dir_in;                 /* count for output packets */
    uint32_t    dir_out;                /* count for input packets */
    bool        is_info_set;
};

struct file_basic_stats {
    FILE        *file;
    uint32_t    num_lines;
    uint32_t    flow_count;
    char        prefix[MAX_NAME_LENGTH];
    double first_flow_start_time;
    struct flow_info *flow_list;
    struct first_line_fields *first_line_stats;
    struct last_line_fields *last_line_stats;
};

extern bool verbose;
void stats_into_plot_file(struct file_basic_stats *f_basics, uint32_t flowid,
                          char plot_file_name[]);

bool
is_flowid_in_file(const struct file_basic_stats *f_basics, uint32_t flowid, int *idx)
{
    for (uint32_t i = 0; i < f_basics->flow_count; i++) {
        if (f_basics->flow_list[i].flowid == flowid) {
            *idx = i;
            return true;
        }
    }
    return false;
}

void
fill_flow_info(struct flow_info *target_flow, char *fields[])
{
    if (target_flow != NULL) {
        target_flow->flowid = (uint32_t)my_atol(fields[FL_FLOW_ID], BASE16);
        snprintf(target_flow->laddr, sizeof(target_flow->laddr), "%s", fields[FL_LOIP]);
        target_flow->lport = (uint16_t)my_atol(fields[FL_LPORT], BASE10);
        snprintf(target_flow->faddr, sizeof(target_flow->faddr), "%s", fields[FL_FOIP]);
        target_flow->fport = (uint16_t)my_atol(fields[FL_FPORT], BASE10);
        target_flow->ipver = INP_IPV4;
        target_flow->stack_type = (int)my_atol(fields[FL_STACK_TYPE], BASE10);
        target_flow->tcp_cc = (int)my_atol(fields[FL_TCP_CC], BASE10);
        target_flow->mss = (uint32_t)my_atol(fields[FL_MSS], BASE10);
        target_flow->isSACK = (bool)my_atol(fields[FL_ISSACK], BASE10);
        target_flow->snd_scale = (uint8_t)my_atol(fields[FL_SNDSCALE], BASE10);
        target_flow->rcv_scale = (uint8_t)my_atol(fields[FL_RCVSCALE], BASE10);
        target_flow->record_cnt = (uint32_t)my_atol(fields[FL_NUMRECORD], BASE10);
        target_flow->trans_cnt = (uint32_t)my_atol(fields[FL_NTRANS], BASE10);
        target_flow->dir_in = 0;
        target_flow->dir_out = 0;
        target_flow->is_info_set = true;
    }
}

/* Function to read the last line of a file */
int
read_last_line(FILE *file, char *lastLine)
{
    long fileSize;
    int pos;

    if (lastLine == NULL) {
        PERROR_FUNCTION("empty buffer");
        return EXIT_FAILURE;
    }

    fseek(file, 0, SEEK_END);
    fileSize = ftell(file);

    for (pos = 1; pos < fileSize; pos++) {
        fseek(file, -pos, SEEK_END);
        if (fgetc(file) == '\n') {
            if (fgets(lastLine, MAX_LINE_LENGTH, file) != NULL) {
                return EXIT_SUCCESS;
            }
        }
    }
    /* If file has only one line, handle that case */
    rewind(file);
    if (fgets(lastLine, MAX_LINE_LENGTH, file) != NULL) {
        return EXIT_SUCCESS;
    } else {
        PERROR_FUNCTION("fgets");
        return EXIT_FAILURE;
    }
}

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
    } else if (type == FOOT && field_cnt != TOTAL_FLOWLIST_FIELDS) {
        printf("\nfield_cnt:%d != TOTAL_FLOWLIST_FIELDS:%d\n",
               field_cnt, TOTAL_FLOWLIST_FIELDS);
        PERROR_FUNCTION("field_cnt != TOTAL_FLOWLIST_FIELDS");
    }
}

static inline void
get_first_line_stats(struct file_basic_stats *f_basics)
{
    FILE *file = f_basics->file;
    struct first_line_fields *f_line_stats = NULL;
    char *firstLine = (char *)calloc(MAX_LINE_LENGTH, sizeof(char));
    if (firstLine == NULL) {
        PERROR_FUNCTION("malloc");
        return;
    }

    /* read the last line of a file */
    if (fgets(firstLine, MAX_LINE_LENGTH, file) != NULL) {
        /* 6 fields in the first line */
        char *fields[TOTAL_FIRST_LINE_FIELDS];
        uint32_t field_count = 0;
        f_line_stats = (struct first_line_fields *)malloc(sizeof(*f_line_stats));

        /* Strip newline characters at the end */
        firstLine[strcspn(firstLine, "\r\n")] = '\0';

        /* Tokenize the line using comma as the delimiter */
        char *token = strtok(firstLine, TAB_DELIMITER);
        while (token != NULL) {
            fields[field_count++] = token;
            token = strtok(NULL, TAB_DELIMITER);
        }

        f_line_stats->enable_time.tv_sec = GET_VALUE(fields[ENABLE_TIME_SECS]);
        f_line_stats->enable_time.tv_usec = GET_VALUE(fields[ENABLE_TIME_USECS]);
        snprintf(f_line_stats->siftrver, sizeof(f_line_stats->siftrver), "%s",
                 next_sub_str_from(fields[SIFTRVER], EQUAL_DELIMITER));
        snprintf(f_line_stats->sysname, sizeof(f_line_stats->sysname), "%s",
                 next_sub_str_from(fields[SYSNAME], EQUAL_DELIMITER));
        snprintf(f_line_stats->sysver, sizeof(f_line_stats->sysver), "%s",
                 next_sub_str_from(fields[SYSVER], EQUAL_DELIMITER));
        snprintf(f_line_stats->ipmode, sizeof(f_line_stats->ipmode), "%s",
                 next_sub_str_from(fields[IPMODE], EQUAL_DELIMITER));

        free(firstLine);
    } else {
        free(firstLine);
        PERROR_FUNCTION("Failed to read the first line.");
        return;
    }

    if (verbose) {
        printf("enable_time: %ld.%ld, siftrver: %s, sysname: %s, sysver: %s, "
                "ipmode: %s\n\n",
                (long)f_line_stats->enable_time.tv_sec,
                (long)f_line_stats->enable_time.tv_usec,
                f_line_stats->siftrver,
                f_line_stats->sysname,
                f_line_stats->sysver,
                f_line_stats->ipmode);
    }

    f_basics->first_line_stats = f_line_stats;
}

static inline void
get_last_line_stats(struct file_basic_stats *f_basics)
{
    FILE *file = f_basics->file;
    struct last_line_fields *l_line_stats = NULL;
    char *lastLine = (char *)calloc(MAX_LINE_LENGTH, sizeof(char));
    if (lastLine == NULL) {
        PERROR_FUNCTION("malloc");
        return;
    }

    if (read_last_line(file, lastLine) == EXIT_SUCCESS) {
        char *fields[TOTAL_LAST_LINE_FIELDS];
        uint32_t field_count = 0;
        l_line_stats = (struct last_line_fields *)malloc(sizeof(*l_line_stats));
        if (l_line_stats == NULL) {
            PERROR_FUNCTION("malloc failed for l_line_stats");
        }

        /* includes the null terminator */
        l_line_stats->line_len = strlen(lastLine) + 1;

        /* Strip newline characters at the end */
        lastLine[strcspn(lastLine, "\r\n")] = '\0';

        // Tokenize the line using tab as the delimiter
        char *token = strtok(lastLine, TAB_DELIMITER);
        while (token != NULL) {
            fields[field_count++] = token;
            token = strtok(NULL, TAB_DELIMITER);
        }

        if (field_count != TOTAL_LAST_LINE_FIELDS) {
            PERROR_FUNCTION("field_count != TOTAL_LAST_LINE_FIELDS");
        }

        l_line_stats->disable_time.tv_sec = GET_VALUE(fields[DISABLE_TIME_SECS]);
        l_line_stats->disable_time.tv_usec = GET_VALUE(fields[DISABLE_TIME_USECS]);

        l_line_stats->global_flow_cnt = GET_VALUE(fields[GLOBAL_FLOW_CNT]);
        l_line_stats->max_tmp_qsize = GET_VALUE(fields[MAX_TMP_QSIZE]);
        l_line_stats->avg_tmp_qsize = GET_VALUE(fields[AVG_TMP_QSIZE]);
        l_line_stats->max_str_size = GET_VALUE(fields[MAX_STR_SIZE]);
        l_line_stats->alq_getn_fail_cnt = GET_VALUE(fields[ALQ_GETN_FAIL_CNT]);
        l_line_stats->gen_flowid_cnt = GET_VALUE(fields[GEN_FLOWID_CNT]);

        char *sub_str = next_sub_str_from(fields[FLOW_LIST], EQUAL_DELIMITER);

        l_line_stats->flow_list_str = strdup(sub_str);
        if (l_line_stats->flow_list_str == NULL) {
            PERROR_FUNCTION("Failed to strdup the last line.");
        }

        free(lastLine);
    } else {
        free(lastLine);
        PERROR_FUNCTION("Failed to read the last line.");
        return;
    }

    if (verbose) {
        printf("disable_time: %ld.%ld, global_flow_cnt: %u, max_tmp_qsize: %u, "
               "avg_tmp_qsize: %u, max_str_size: %u, alq_getn_fail_cnt: %u, "
               "gen_flowid_cnt: %u, flow_list: %s\n\n",
               (long)l_line_stats->disable_time.tv_sec,
               (long)l_line_stats->disable_time.tv_usec,
               l_line_stats->global_flow_cnt,
               l_line_stats->max_tmp_qsize,
               l_line_stats->avg_tmp_qsize,
               l_line_stats->max_str_size,
               l_line_stats->alq_getn_fail_cnt,
               l_line_stats->gen_flowid_cnt,
               l_line_stats->flow_list_str);
    }

    f_basics->last_line_stats = l_line_stats;
    assert(l_line_stats->line_len >= l_line_stats->max_str_size);
}

static void
print_flow_info(struct flow_info *flow_info)
{
    printf(" id:%08x (%s:%hu<->%s:%hu) stack:%s tcp_cc:%s mss:%u SACK:%d"
           " snd/rcv_scal:%hhu/%hhu cnt:%u/%u\n",
           flow_info->flowid,
           flow_info->laddr, flow_info->lport,
           flow_info->faddr, flow_info->fport,
           (flow_info->stack_type == RACK) ? "rack" : "fbsd",
           (flow_info->tcp_cc == CUBIC) ? "CUBIC" : "NewReno",
           flow_info->mss, flow_info->isSACK,
           flow_info->snd_scale, flow_info->rcv_scale,
           flow_info->record_cnt, flow_info->trans_cnt);
}

static inline void
get_flow_count_and_info(struct file_basic_stats *f_basics)
{
    uint32_t flow_cnt = f_basics->last_line_stats->global_flow_cnt;
    char **flow_list_arr;

    char *flow_list_str = strdup(f_basics->last_line_stats->flow_list_str);
    if (flow_list_str == NULL) {
        PERROR_FUNCTION("strdup() failed for flow_list_str");
        return;
    }
    if (flow_cnt == 0) {
        printf("%s%u: no flow in flow list of the foot note:%u\n",
               __FUNCTION__, __LINE__, flow_cnt);
        PERROR_FUNCTION("flow list not set");
        return;
    }
    f_basics->flow_count = flow_cnt;
    f_basics->flow_list = (struct flow_info*)calloc(flow_cnt, sizeof(struct flow_info));
    flow_list_arr = (char **)malloc(flow_cnt * sizeof(char **));

    flow_cnt = 0;
    /* get the total number of flows */
    char *token = strtok(flow_list_str, SEMICOLON_DELIMITER);
    while (token != NULL) {
        flow_list_arr[flow_cnt] = token;
        flow_cnt++;
        token = strtok(NULL, SEMICOLON_DELIMITER);
    }

    assert(flow_cnt == f_basics->last_line_stats->global_flow_cnt);

    for (uint32_t i = 0; i < flow_cnt; i++) {
        char *fields[TOTAL_FLOWLIST_FIELDS];
        struct flow_info target_flow;

        fill_fields_from_line(fields, flow_list_arr[i], FOOT);
        fill_flow_info(&target_flow, fields);
        f_basics->flow_list[i] = target_flow;
    }

    free(flow_list_arr);
    free(flow_list_str);
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

    get_first_line_stats(f_basics);
    if (f_basics->first_line_stats == NULL) {
        PERROR_FUNCTION("head note not exist");
        return EXIT_FAILURE;
    }

    get_last_line_stats(f_basics);
    if (f_basics->last_line_stats == NULL) {
        PERROR_FUNCTION("foot note not exist");
        return EXIT_FAILURE;
    }

    get_flow_count_and_info(f_basics);

    return EXIT_SUCCESS;
}

void
show_file_basic_stats(const struct file_basic_stats *f_basics)
{
    struct timeval result;
    double time_in_seconds;
    time_t seconds;
    struct tm *time_info;
    char buffer[30];

    timeval_subtract(&result, &f_basics->last_line_stats->disable_time,
                     &f_basics->first_line_stats->enable_time);

    time_in_seconds = result.tv_sec + result.tv_usec / 1000000.0;

    printf("siftr version: %s\n", f_basics->first_line_stats->siftrver);

    if (verbose) {
        printf("flow list: %s\n", f_basics->last_line_stats->flow_list_str);
    }

    printf("flow id list:\n");
    for (uint32_t i = 0; i < f_basics->flow_count; i++) {
        print_flow_info(&f_basics->flow_list[i]);
    }
    printf("\n");

    // Extract seconds part of timeval
    seconds = f_basics->first_line_stats->enable_time.tv_sec;
    // Convert to calendar time
    time_info = localtime(&seconds);
    strftime(buffer, sizeof(buffer), "%Y-%m-%d %H:%M:%S", time_info);

    printf("starting_time: %s.%06ld (%jd.%06ld)\n", buffer,
	   (intmax_t)f_basics->first_line_stats->enable_time.tv_usec,
           f_basics->first_line_stats->enable_time.tv_sec,
           (intmax_t)f_basics->first_line_stats->enable_time.tv_usec);

    // Extract seconds part of timeval
    seconds = f_basics->last_line_stats->disable_time.tv_sec;
    // Convert to calendar time
    time_info = localtime(&seconds);
    strftime(buffer, sizeof(buffer), "%Y-%m-%d %H:%M:%S", time_info);

    printf("ending_time: %s.%06ld (%jd.%06ld)\n", buffer,
	   (intmax_t)f_basics->last_line_stats->disable_time.tv_usec,
           f_basics->last_line_stats->disable_time.tv_sec,
           (intmax_t)f_basics->last_line_stats->disable_time.tv_usec);

    printf("log duration: %.2f seconds\n", time_in_seconds);
}

/* Read the body of the per-flow stats, and skip the head or foot note. */
void
read_body_by_flowid(struct file_basic_stats *f_basics, uint32_t flowid)
{
    int idx;

    if (is_flowid_in_file(f_basics, flowid, &idx)) {
        char plot_file_name[MAX_NAME_LENGTH];
        // Combine the strings into the plot_file buffer
        if (strlen(f_basics->prefix) == 0) {
            snprintf(plot_file_name, MAX_NAME_LENGTH, "plot_%08x.txt", flowid);
        } else {
            snprintf(plot_file_name, MAX_NAME_LENGTH, "%s.%08x.txt",
                     f_basics->prefix, flowid);
        }

        printf("plot_file_name: %s\n", plot_file_name);

        printf("++++++++++++++++++++++++++++++ summary ++++++++++++++++++++++++++++\n");
        printf("  %s:%hu->%s:%hu flowid: %08x\n",
               f_basics->flow_list[idx].laddr, f_basics->flow_list[idx].lport,
               f_basics->flow_list[idx].faddr, f_basics->flow_list[idx].fport,
               flowid);
        stats_into_plot_file(f_basics, flowid, plot_file_name);

        printf("           has %u useful records (%u outputs, %u inputs)\n",
               f_basics->flow_list[idx].record_cnt,
               f_basics->flow_list[idx].dir_out,
               f_basics->flow_list[idx].dir_in);

        assert(f_basics->flow_list[idx].record_cnt ==
               (f_basics->flow_list[idx].dir_in +
                f_basics->flow_list[idx].dir_out));
    } else {
        printf("flow ID %u not found\n", flowid);
    }
}

int
cleanup_file_basic_stats(const struct file_basic_stats *f_basics_ptr)
{

    // Close the file and check for errors
    if (fclose(f_basics_ptr->file) == EOF) {
        PERROR_FUNCTION("Failed to close file");
        return EXIT_FAILURE;
    }

    free(f_basics_ptr->first_line_stats);
    free(f_basics_ptr->last_line_stats->flow_list_str);
    free(f_basics_ptr->last_line_stats);
    free(f_basics_ptr->flow_list);

    return EXIT_SUCCESS;
}

#endif /* REVIEW_SIFTR2_LOG_H_ */
