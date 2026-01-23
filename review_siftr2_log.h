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
#include <limits.h>
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

// header fields
/* first_line_fields.def */
#define FIRST_LINE_FIELDS(X)          \
    X(ENABLE_TIME_SECS)               \
    X(ENABLE_TIME_USECS)              \
    X(SIFTRVER)                       \
    X(REC_FMT)                        \
    X(SYSVER)

enum {
#define X(name) name,
    FIRST_LINE_FIELDS(X)
#undef X
    TOTAL_FIRST_LINE_FIELDS
};

struct first_line_fields {
    struct timeval enable_time;
    char siftrver[EIGHT_BYTES_LEN];
    char rec_fmt[EIGHT_BYTES_LEN];
    char sysver[NAME_MAX];
};

_Static_assert(TOTAL_FIRST_LINE_FIELDS == 5, "First line format changed");

// footer fields
/* last_line_fields.def */
#define LAST_LINE_FIELDS(X)         \
    X(DISABLE_TIME_SECS)            \
    X(DISABLE_TIME_USECS)           \
    X(GLOBAL_FLOW_CNT)              \
    X(RING_DROPS)                   \
    X(MAX_STR_SIZE)                 \
    X(GEN_FLOWID_CNT)               \
    X(FLOW_LIST)                    \

enum {
#define X(name) name,
    LAST_LINE_FIELDS(X)
#undef X
    TOTAL_LAST_LINE_FIELDS
};

struct last_line_fields {
    struct timeval disable_time;
    uint32_t global_flow_cnt;
    uint32_t ring_drops;
    uint32_t max_str_size;       // is `record_size` if the log is binary format
    uint32_t gen_flowid_cnt;
    uint32_t line_len;           /* includes the null terminator */
    char     *flow_list_str;
};

_Static_assert(TOTAL_LAST_LINE_FIELDS == 7, "First line format changed");

/* flow list fields in the foot note of the siftr2 log */
enum {
    FL_FLOW_ID,     FL_IPVER,       FL_LOIP,        FL_LPORT,
    FL_FOIP,        FL_FPORT,       FL_TCP_STACK_NAME,  FL_TCP_CC_NAME,
    FL_MSS,         FL_ISSACK,      FL_SNDSCALE,    FL_RCVSCALE,
    FL_NUMRECORD,   FL_NTRANS,      TOTAL_FLOWLIST_FIELDS,
};

/* TCP traffic record fields */
enum {
    FLOW_ID,        DIRECTION,      RELATIVE_TIME,      CWND,   SSTHRESH,
    SRTT,           TCP_DATA_SZ,
    SNDWIN,         RCVWIN,         FLAG,           FLAG2,          RTO,
    SND_BUF_HIWAT,  SND_BUF_CC,     RCV_BUF_HIWAT,  RCV_BUF_CC,
    INFLIGHT_BYTES, REASS_QLEN,
    TOTAL_FIELDS,
};

/* TCP traffic record structure from siftr2.c */
struct pkt_node {
    /* Flowid for the connection. */
    uint32_t        flowid;
    /* Direction pkt is travelling. */
    enum {
        DIR_IN = 0,
        DIR_OUT = 1,
    }           direction;
    /* Timestamp (milliseconds) since SIFTR enable. */
    uint32_t        tval;
    /* Congestion Window (bytes). */
    uint32_t        snd_cwnd;
    /* Slow Start Threshold (bytes). */
    uint32_t        snd_ssthresh;
    /* Smoothed RTT (usecs). */
    uint32_t        srtt;
    /* the length of TCP segment payload in bytes */
    uint32_t        data_sz;
    /* Sending Window (bytes). */
    uint32_t        snd_wnd;
    /* Receive Window (bytes). */
    uint32_t        rcv_wnd;
    /* TCP control block flags. */
    uint32_t        t_flags;
    /* More tcpcb flags storage */
    uint32_t        t_flags2;
    /* Retransmission timeout (usec). */
    uint32_t        rto;
    /* Size of the TCP send buffer in bytes. */
    uint32_t        snd_buf_hiwater;
    /* Current num bytes in the send socket buffer. */
    uint32_t        snd_buf_cc;
    /* Size of the TCP receive buffer in bytes. */
    uint32_t        rcv_buf_hiwater;
    /* Current num bytes in the receive socket buffer. */
    uint32_t        rcv_buf_cc;
    /* Number of bytes inflight that we are waiting on ACKs for. */
    uint32_t        pipe;
    /* Number of segments currently in the reassembly queue. */
    int32_t         t_segqlen;
} __packed;

_Static_assert(sizeof(struct pkt_node) == 72, "pkt_node must be 72 bytes");

struct flow_info {
    /* permanent info */
    uint32_t    flowid;                     /* flowid of the connection */
    char        laddr[INET6_ADDRSTRLEN];    /* local IP address */
    char        faddr[INET6_ADDRSTRLEN];    /* foreign IP address */
    uint16_t    lport;                      /* local TCP port */
    uint16_t    fport;                      /* foreign TCP port */
    uint8_t     ipver;                      /* IP version */
    /* infrequently change info */
    char        tcp_stack_name[NAME_MAX];   /* TCP stack name: freebsd or rack */
    char        tcp_cc_name[NAME_MAX];      /* TCP congestion control name */
    uint32_t    mss;
    bool        isSACK;
    uint8_t     snd_scale;                  /* Window scaling for snd window. */
    uint8_t     rcv_scale;                  /* Window scaling for recv window. */

    uint64_t    record_cnt;             /* num of records in the log */
    uint64_t    trans_cnt;              /* num of all transfers (in/out) */
    uint64_t    dir_in;                 /* count for output packets */
    uint64_t    dir_out;                /* count for input packets */

    uint64_t    data_pkt_cnt;
    uint64_t    total_data_sz;
    uint16_t    min_payload_sz;
    uint16_t    max_payload_sz;
    uint64_t    fragment_cnt;

    uint64_t    srtt_sum;
    uint32_t    srtt_min;
    uint32_t    srtt_max;

    uint64_t    cwnd_sum;
    uint32_t    cwnd_min;
    uint32_t    cwnd_max;

    bool        is_info_set;
};

struct file_basic_stats {
    FILE        *file;
    uint64_t    num_lines;
    uint64_t    num_records;
    uint32_t    flow_count;
    char        prefix[NAME_MAX - 20];
    uint32_t    first_flow_start_time;
    long        last_line_offset;
    struct flow_info *flow_list;
    struct first_line_fields *first_line_stats;
    struct last_line_fields *last_line_stats;
};

bool verbose = false;
bool is_rec_fmt_binary = false;
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
init_flow_info(struct flow_info *target_flow, char *fields[])
{
    if (target_flow != NULL) {
        target_flow->flowid = (uint32_t)my_atol(fields[FL_FLOW_ID], BASE16);
        target_flow->ipver = (uint8_t)my_atol(fields[FL_IPVER], BASE10);
        snprintf(target_flow->laddr, sizeof(target_flow->laddr), "%s", fields[FL_LOIP]);
        target_flow->lport = (uint16_t)my_atol(fields[FL_LPORT], BASE10);
        snprintf(target_flow->faddr, sizeof(target_flow->faddr), "%s", fields[FL_FOIP]);
        target_flow->fport = (uint16_t)my_atol(fields[FL_FPORT], BASE10);

        snprintf(target_flow->tcp_stack_name, sizeof(target_flow->tcp_stack_name),
                 "%s", fields[FL_TCP_STACK_NAME]);
        snprintf(target_flow->tcp_cc_name, sizeof(target_flow->tcp_cc_name),
                 "%s", fields[FL_TCP_CC_NAME]);

        target_flow->mss = (uint32_t)my_atol(fields[FL_MSS], BASE10);
        target_flow->isSACK = (bool)my_atol(fields[FL_ISSACK], BASE10);
        target_flow->snd_scale = (uint8_t)my_atol(fields[FL_SNDSCALE], BASE10);
        target_flow->rcv_scale = (uint8_t)my_atol(fields[FL_RCVSCALE], BASE10);
        target_flow->record_cnt = (uint32_t)my_atol(fields[FL_NUMRECORD], BASE10);
        target_flow->trans_cnt = (uint32_t)my_atol(fields[FL_NTRANS], BASE10);
        target_flow->dir_in = 0;
        target_flow->dir_out = 0;

        target_flow->data_pkt_cnt = 0;
        target_flow->total_data_sz = 0;
        target_flow->min_payload_sz = UINT16_MAX;
        target_flow->max_payload_sz = 0;
        target_flow->fragment_cnt = 0;

        target_flow->srtt_sum = 0;
        target_flow->srtt_min = UINT32_MAX;
        target_flow->srtt_max = 0;

        target_flow->cwnd_sum = 0;
        target_flow->cwnd_min = UINT32_MAX;
        target_flow->cwnd_max = 0;

        target_flow->is_info_set = true;
    }
}

/* Function to read the last line of a file */
int
read_last_line(struct file_basic_stats *f_basics, char *lastLine)
{
    long fileSize;
    int pos;
    FILE *file = f_basics->file;

    if (lastLine == NULL) {
        PERROR_FUNCTION("empty buffer");
        return EXIT_FAILURE;
    }

    fseek(file, 0, SEEK_END);
    fileSize = ftell(file);

    for (pos = 1; pos < fileSize; pos++) {
        fseek(file, -pos, SEEK_END);
        if (fgetc(file) == '\n') {
            // After finding '\n' by scanning back:
            f_basics->last_line_offset = ftell(file);
            if (fgets(lastLine, PATH_MAX, file) != NULL) {
                return EXIT_SUCCESS;
            }
        }
    }
    /* If file has only one line, handle that case */
    rewind(file);
    if (fgets(lastLine, sizeof(lastLine), file) != NULL) {
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

static inline bool
file_has_3lines(const struct file_basic_stats *f_basics)
{
    int c;
    int newline_cnt = 0;

    rewind(f_basics->file);
    while ((c = fgetc(f_basics->file)) != EOF) {
        if (c == '\n') {
            newline_cnt++;
            if (newline_cnt > 2) { // 3 lines => at least 2 newline characters
                break;
            }
        }
    }
    if (newline_cnt <= 2) {
        PERROR_FUNCTION("File must contain at least 3 lines for head, body and foot.");
        fclose(f_basics->file);
        return (false);
    }
    return (true);
}

static inline void
get_first_2lines_stats(struct file_basic_stats *f_basics)
{
    FILE *file = f_basics->file;
    struct first_line_fields *f_line_stats = NULL;
    char line[PATH_MAX] = {};

    /* read the first line of the file */
    if (fgets(line, sizeof(line), file) != NULL) {
        /* 6 fields in the first line */
        char *fields[TOTAL_FIRST_LINE_FIELDS];
        uint32_t field_count = 0;
        f_line_stats = (struct first_line_fields *)malloc(sizeof(*f_line_stats));

        /* Strip newline characters at the end */
        line[strcspn(line, "\r\n")] = '\0';

        /* Tokenize the line using comma as the delimiter */
        char *token = strtok(line, TAB_DELIMITER);
        while (token != NULL) {
            fields[field_count++] = token;
            token = strtok(NULL, TAB_DELIMITER);
        }

        f_line_stats->enable_time.tv_sec = GET_VALUE(fields[ENABLE_TIME_SECS]);
        f_line_stats->enable_time.tv_usec = GET_VALUE(fields[ENABLE_TIME_USECS]);
        snprintf(f_line_stats->siftrver, sizeof(f_line_stats->siftrver), "%s",
                 next_sub_str_from(fields[SIFTRVER], EQUAL_DELIMITER));
        snprintf(f_line_stats->rec_fmt, sizeof(f_line_stats->rec_fmt), "%s",
                 next_sub_str_from(fields[REC_FMT], EQUAL_DELIMITER));
        snprintf(f_line_stats->sysver, sizeof(f_line_stats->sysver), "%s",
                 next_sub_str_from(fields[SYSVER], EQUAL_DELIMITER));

        if (strncmp(f_line_stats->rec_fmt, "binary", sizeof("binary")) == 0) {
            is_rec_fmt_binary = true;
        }

    } else {
        PERROR_FUNCTION("Failed to read the first line.");
        return;
    }

    {
        /* read the first record at the second line of the file */
        if (is_rec_fmt_binary) {
            struct pkt_node node;
            size_t rec_size = sizeof(struct pkt_node);
            if (fread(&node, 1, rec_size, file) != 0) {
                f_basics->first_flow_start_time = node.tval;
            }
        } else {
            if (fgets(line, sizeof(line), file) == NULL) {
                PERROR_FUNCTION("Failed to read the second line");
                return;
            }
            char *fields[TOTAL_FIELDS];
            fill_fields_from_line(fields, line, BODY);
            f_basics->first_flow_start_time = fast_hex_to_u32(fields[RELATIVE_TIME]);
        }
    }

    if (verbose) {
        printf("enable_time: %ld.%ld, siftrver: %s, rec_fmt: %s, "
               "sysver: %s\n",
               (long)f_line_stats->enable_time.tv_sec,
               (long)f_line_stats->enable_time.tv_usec,
               f_line_stats->siftrver,
               f_line_stats->rec_fmt,
               f_line_stats->sysver);

        printf("first flow start at: %.3f\n\n", f_basics->first_flow_start_time / 1000.0f);
    }

    f_basics->first_line_stats = f_line_stats;
}

static inline void
get_last_line_stats(struct file_basic_stats *f_basics)
{
    struct last_line_fields *l_line_stats = NULL;
    char line[PATH_MAX] = {};

    if (read_last_line(f_basics, line) == EXIT_SUCCESS) {
        char *fields[TOTAL_LAST_LINE_FIELDS];
        uint32_t field_count = 0;
        l_line_stats = (struct last_line_fields *)malloc(sizeof(*l_line_stats));
        if (l_line_stats == NULL) {
            PERROR_FUNCTION("malloc failed for l_line_stats");
        }

        /* includes the null terminator */
        l_line_stats->line_len = strlen(line) + 1;

        /* Strip newline characters at the end */
        line[strcspn(line, "\r\n")] = '\0';

        // Tokenize the line using tab as the delimiter
        char *token = strtok(line, TAB_DELIMITER);
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
        l_line_stats->ring_drops = GET_VALUE(fields[RING_DROPS]);
        l_line_stats->max_str_size = GET_VALUE(fields[MAX_STR_SIZE]);
        l_line_stats->gen_flowid_cnt = GET_VALUE(fields[GEN_FLOWID_CNT]);

        char *sub_str = next_sub_str_from(fields[FLOW_LIST], EQUAL_DELIMITER);

        l_line_stats->flow_list_str = strdup(sub_str);
        if (l_line_stats->flow_list_str == NULL) {
            PERROR_FUNCTION("Failed to strdup the last line.");
        }
    } else {
        PERROR_FUNCTION("Failed to read the last line.");
        return;
    }

    if (verbose) {
        printf("disable_time: %ld.%ld, global_flow_cnt: %u, ring_drops: %u, "
               "max_str_size: %u, gen_flowid_cnt: %u, flow_list: %s\n\n",
               (long)l_line_stats->disable_time.tv_sec,
               (long)l_line_stats->disable_time.tv_usec,
               l_line_stats->global_flow_cnt,
               l_line_stats->ring_drops,
               l_line_stats->max_str_size,
               l_line_stats->gen_flowid_cnt,
               l_line_stats->flow_list_str);
    }

    f_basics->last_line_stats = l_line_stats;
    assert(l_line_stats->line_len >= l_line_stats->max_str_size);
}

static void
print_flow_info(struct flow_info *flow_info)
{
    printf(" id:%08x %s (%s:%hu<->%s:%hu) stack:%s tcp_cc:%s mss:%u SACK:%d"
           " snd/rcv_scal:%hhu/%hhu cnt:%" PRIu64 "/%" PRIu64 "\n",
           flow_info->flowid, (flow_info->ipver == IPV4) ? "IPv4" : "IPv6",
           flow_info->laddr, flow_info->lport,
           flow_info->faddr, flow_info->fport,
           flow_info->tcp_stack_name, flow_info->tcp_cc_name,
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
        init_flow_info(&target_flow, fields);
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

    if (!file_has_3lines(f_basics)) {
        return EXIT_FAILURE;
    }
    rewind(file);

    get_first_2lines_stats(f_basics);
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

    printf("ending_time:   %s.%06ld (%jd.%06ld)\n", buffer,
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

    printf("input flow id is: %08x\n", flowid);

    if (is_flowid_in_file(f_basics, flowid, &idx)) {
        char plot_file_name[NAME_MAX];
        struct flow_info *f_info = &f_basics->flow_list[idx];

        // Combine the strings into the plot_file buffer
        if (strlen(f_basics->prefix) == 0) {
            snprintf(plot_file_name, NAME_MAX, "plot_%08x.txt", flowid);
        } else {
            snprintf(plot_file_name, NAME_MAX, "%s.%08x.txt",
                     f_basics->prefix, flowid);
        }

        stats_into_plot_file(f_basics, flowid, plot_file_name);

        if (is_rec_fmt_binary) {
            printf("input file has total records: %" PRIu64 "\n", f_basics->num_records);
        } else {
            printf("input file has total lines: %" PRIu64 "\n", f_basics->num_lines);
        }
        printf("plot_file_name: %s\n", plot_file_name);

        printf("++++++++++++++++++++++++++++++ summary ++++++++++++++++++++++++++++\n");
        printf("  %s:%hu->%s:%hu flowid: %08x\n",
               f_info->laddr, f_info->lport, f_info->faddr, f_info->fport,
               flowid);

        printf("input flow data_pkt_cnt: %" PRIu64 ", fragment_cnt: %" PRIu64
               ", fragment_ratio: %.3f\n"
               "           avg_payload: %.0f, min_payload: %u, max_payload: %u bytes\n"
               "           avg_srtt: %" PRIu64 ", min_srtt: %u, max_srtt: %u µs\n"
               "           avg_cwnd: %" PRIu64 ", min_cwnd: %u, max_cwnd: %u bytes\n",
               f_info->data_pkt_cnt, f_info->fragment_cnt,
               (double)f_info->fragment_cnt / f_info->data_pkt_cnt,
               (double)f_info->total_data_sz / f_info->data_pkt_cnt,
               f_info->min_payload_sz, f_info->max_payload_sz,
               f_info->srtt_sum / f_info->record_cnt,
               f_info->srtt_min, f_info->srtt_max,
               f_info->cwnd_sum / f_info->record_cnt,
               f_info->cwnd_min, f_info->cwnd_max);


        printf("           has %" PRIu64 " useful records "
               "(%" PRIu64 " outputs, %" PRIu64 " inputs)\n",
               f_basics->flow_list[idx].record_cnt,
               f_basics->flow_list[idx].dir_out,
               f_basics->flow_list[idx].dir_in);

        assert(f_basics->flow_list[idx].record_cnt ==
               (f_basics->flow_list[idx].dir_in +
                f_basics->flow_list[idx].dir_out));
    } else {
        printf("but the flow id: %08x not found in file\n", flowid);
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
