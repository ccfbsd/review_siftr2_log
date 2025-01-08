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

typedef uint32_t tcp_seq;

enum {
    INP_IPV4 = 0x1,		// siftr2 is IPv4 only
    MAX_LINE_LENGTH = 1000,
    MAX_NAME_LENGTH = 100,
    INET6_ADDRSTRLEN = 46,
    TF_ARRAY_MAX_LENGTH = 550,
    TF2_ARRAY_MAX_LENGTH = 560,
    PER_FLOW_STRING_LENGTH = (INET6_ADDRSTRLEN*2 + 5*2 + 1),
};

#define COMMA_DELIMITER     ","
#define TAB_DELIMITER       "\t"
#define TAB         TAB_DELIMITER
#define EQUAL_DELIMITER     "="
#define SEMICOLON_DELIMITER     ";"

#define PERROR_FUNCTION(msg) \
        do {                                                                \
            fprintf(stderr, "Error in %s:%s:%u ",                           \
                    __FILE__, __FUNCTION__, __LINE__);                      \
            perror(msg);                                                    \
        } while(0)

#define GET_VALUE(field) \
        my_atol(next_sub_str_from(field, EQUAL_DELIMITER));

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

struct first_line_fields {
    char        siftrver[8];
    char        sysname[8];
    char        sysver[8];
    char        ipmode[8];
    struct timeval enable_time;
};

enum {
    DISABLE_TIME_SECS,
    DISABLE_TIME_USECS,
    GLOBAL_FLOW_CNT,
    MAX_TMP_QSIZE,
    AVG_TMP_QSIZE,
    MAX_STR_SIZE,
    ALQ_GETN_FAIL_CNT,
    FLOW_LIST,
    TOTAL_LAST_LINE_FIELDS,
};

struct last_line_fields {
    uint32_t    global_flow_cnt;
    uint32_t    max_tmp_qsize;
    uint32_t    avg_tmp_qsize;
    uint32_t    max_str_size;
    uint32_t    alq_getn_fail_cnt;
    uint32_t    line_len;
    char        *flow_list_str;
    struct timeval disable_time;
};

/* flow list fields in the foot note of the siftr2 log */
enum {
    FL_FLOW_ID,     FL_LOIP,        FL_LPORT,       FL_FOIP,    FL_FPORT,
    FL_MSS,         FL_ISSACK,      FL_SNDSCALE,    FL_RCVSCALE,
    FL_NUMRECORD,   TOTAL_FLOWLIST_FIELDS,
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

struct pkt_info {
    uint32_t    flowid;     /* flowid of the connection */
    tcp_seq     th_seq;     /* TCP sequence number */
    tcp_seq     th_ack;     /* TCP acknowledgement number */
    uint32_t    data_sz;    /* the length of TCP segment payload in bytes */
};

static inline void
fill_pkt_info(struct pkt_info *pkt, uint32_t flowid, tcp_seq th_seq,
              tcp_seq th_ack, uint32_t data_sz)
{
    pkt->flowid = flowid;
    pkt->th_seq = th_seq;
    pkt->th_ack = th_ack;
    pkt->data_sz = data_sz;
}

static inline void
print_pkt_info(struct pkt_info *pkt)
{
    printf(" id:%10u th_seq:%u th_ack:%u data_sz:%u\n",
           pkt->flowid, pkt->th_seq, pkt->th_ack, pkt->data_sz);
}

struct flow_info {
    uint32_t    flowid;                     /* flowid of the connection */
    char        laddr[INET6_ADDRSTRLEN];    /* local IP address */
    char        faddr[INET6_ADDRSTRLEN];    /* foreign IP address */
    uint16_t    lport;                      /* local TCP port */
    uint16_t    fport;                      /* foreign TCP port */
    uint8_t     ipver;                      /* IP version */
    uint32_t    mss;
    bool        isSACK;
    uint8_t     snd_scale;                  /* Window scaling for snd window. */
    uint8_t     rcv_scale;                  /* Window scaling for recv window. */
    uint32_t    record_cnt;
    uint32_t    dir_in;                 /* count for output packets */
    uint32_t    dir_out;                /* count for input packets */
    bool        is_info_set;
};

struct file_basic_stats {
    FILE        *file;
    uint32_t    num_lines;
    uint32_t    flow_count;
    struct flow_info *flow_list;
    struct first_line_fields *first_line_stats;
    struct last_line_fields *last_line_stats;
};

/* Flags for the tp->t_flags field. */
enum {
    TF_ACKNOW = 0x00000001, TF_DELACK = 0x00000002, TF_NODELAY = 0x00000004,
    TF_NOOPT = 0x00000008,  TF_SENTFIN = 0x00000010, TF_REQ_SCALE = 0x00000020,
    TF_RCVD_SCALE = 0x00000040, TF_REQ_TSTMP = 0x00000080,
    TF_RCVD_TSTMP = 0x00000100, TF_SACK_PERMIT = 0x00000200,
    TF_NEEDSYN = 0x00000400, TF_NEEDFIN = 0x00000800, TF_NOPUSH = 0x00001000,
    TF_PREVVALID = 0x00002000, TF_WAKESOR = 0x00004000,
    TF_GPUTINPROG = 0x00008000, TF_MORETOCOME = 0x00010000,
    TF_SONOTCONN = 0x00020000, TF_LASTIDLE = 0x00040000,
    TF_RXWIN0SENT = 0x00080000, TF_FASTRECOVERY = 0x00100000,
    TF_WASFRECOVERY = 0x00200000, TF_SIGNATURE = 0x00400000,
    TF_FORCEDATA = 0x00800000, TF_TSO = 0x01000000, TF_TOE = 0x02000000,
    TF_CLOSED = 0x04000000, TF_SENTSYN = 0x08000000, TF_LRD = 0x10000000,
    TF_CONGRECOVERY = 0x20000000, TF_WASCRECOVERY = 0x40000000,
    TF_FASTOPEN = 0x80000000,
};

/* Flags for the extended TCP flags field, tp->t_flags2 */
enum {
    TF2_PLPMTU_BLACKHOLE = 0x00000001, TF2_PLPMTU_PMTUD = 0x00000002,
    TF2_PLPMTU_MAXSEGSNT = 0x00000004, TF2_LOG_AUTO = 0x00000008,
    TF2_DROP_AF_DATA = 0x00000010, TF2_ECN_PERMIT = 0x00000020,
    TF2_ECN_SND_CWR = 0x00000040, TF2_ECN_SND_ECE = 0x00000080,
    TF2_ACE_PERMIT = 0x00000100, TF2_HPTS_CPU_SET = 0x00000200,
    TF2_FBYTES_COMPLETE = 0x00000400, TF2_ECN_USE_ECT1 = 0x00000800,
    TF2_TCP_ACCOUNTING = 0x00001000, TF2_HPTS_CALLS = 0x00002000,
    TF2_MBUF_L_ACKS = 0x00004000, TF2_MBUF_ACKCMP = 0x00008000,
    TF2_SUPPORTS_MBUFQ = 0x00010000, TF2_MBUF_QUEUE_READY = 0x00020000,
    TF2_DONT_SACK_QUEUE = 0x00040000, TF2_CANNOT_DO_ECN = 0x00080000,
    TF2_PROC_SACK_PROHIBIT = 0x00100000, TF2_IPSEC_TSO = 0x00200000,
    TF2_NO_ISS_CHECK = 0x00400000,
};

#define IN_FASTRECOVERY(t_flags)    (t_flags & TF_FASTRECOVERY)
#define IN_CONGRECOVERY(t_flags)    (t_flags & TF_CONGRECOVERY)
#define IN_RECOVERY(t_flags) (t_flags & (TF_CONGRECOVERY | TF_FASTRECOVERY))
#define WAS_RECOVERY(t_flags) (t_flags & (TF_WASFRECOVERY | TF_WASCRECOVERY))

extern bool verbose;
void stats_into_plot_file(struct file_basic_stats *f_basics, uint32_t flowid,
                          char plot_file_name[]);

/* There are 32 flag values for t_flags. So assume the caller has provided a
 * large enough array to hold 32 x sizeof("TF_CONGRECOVERY |") == 544 bytes.
 */
void
translate_tflags(uint32_t flags, char str_array[], size_t arr_size)
{
    assert(arr_size >= (32 * sizeof("TF_CONGRECOVERY")));

    if (flags == 0) {
        strcat(str_array, "N/A");
        return;
    }

    if (flags & TF_ACKNOW) {
        strcat(str_array, "TF_ACKNOW | ");
    }
    if (flags & TF_DELACK) {
        strcat(str_array, "TF_DELACK | ");
    }
    if (flags & TF_NODELAY) {
        strcat(str_array, "TF_NODELAY | ");
    }
    if (flags & TF_NOOPT) {
        strcat(str_array, "TF_NOOPT | ");
    }
    if (flags & TF_SENTFIN) {
        strcat(str_array, "TF_SENTFIN | ");
    }
    if (flags & TF_REQ_SCALE) {
        strcat(str_array, "TF_REQ_SCALE | ");
    }
    if (flags & TF_RCVD_SCALE) {
        strcat(str_array, "TF_RCVD_SCALE | ");
    }
    if (flags & TF_REQ_TSTMP) {
        strcat(str_array, "TF_REQ_TSTMP | ");
    }
    if (flags & TF_RCVD_TSTMP) {
        strcat(str_array, "TF_RCVD_TSTMP | ");
    }
    if (flags & TF_SACK_PERMIT) {
        strcat(str_array, "TF_SACK_PERMIT | ");
    }
    if (flags & TF_NEEDSYN) {
        strcat(str_array, "TF_NEEDSYN | ");
    }
    if (flags & TF_NEEDFIN) {
        strcat(str_array, "TF_NEEDFIN | ");
    }
    if (flags & TF_NOPUSH) {
        strcat(str_array, "TF_NOPUSH | ");
    }
    if (flags & TF_PREVVALID) {
        strcat(str_array, "TF_PREVVALID | ");
    }
    if (flags & TF_WAKESOR) {
        strcat(str_array, "TF_WAKESOR | ");
    }
    if (flags & TF_GPUTINPROG) {
        strcat(str_array, "TF_GPUTINPROG | ");
    }
    if (flags & TF_MORETOCOME) {
        strcat(str_array, "TF_MORETOCOME | ");
    }
    if (flags & TF_SONOTCONN) {
        strcat(str_array, "TF_SONOTCONN | ");
    }
    if (flags & TF_LASTIDLE) {
        strcat(str_array, "TF_LASTIDLE | ");
    }
    if (flags & TF_RXWIN0SENT) {
        strcat(str_array, "TF_RXWIN0SENT | ");
    }
    if (flags & TF_FASTRECOVERY) {
        strcat(str_array, "TF_FASTRECOVERY | ");
    }
    if (flags & TF_WASFRECOVERY) {
        strcat(str_array, "TF_WASFRECOVERY | ");
    }
    if (flags & TF_SIGNATURE) {
        strcat(str_array, "TF_SIGNATURE | ");
    }
    if (flags & TF_FORCEDATA) {
        strcat(str_array, "TF_FORCEDATA | ");
    }
    if (flags & TF_TSO) {
        strcat(str_array, "TF_TSO | ");
    }
    if (flags & TF_TOE) {
        strcat(str_array, "TF_TOE | ");
    }
    if (flags & TF_CLOSED) {
        strcat(str_array, "TF_CLOSED | ");
    }
    if (flags & TF_SENTSYN) {
        strcat(str_array, "TF_SENTSYN | ");
    }
    if (flags & TF_LRD) {
        strcat(str_array, "TF_LRD | ");
    }
    if (flags & TF_CONGRECOVERY) {
        strcat(str_array, "TF_CONGRECOVERY | ");
    }
    if (flags & TF_WASCRECOVERY) {
        strcat(str_array, "TF_WASCRECOVERY | ");
    }
    if (flags & TF_FASTOPEN) {
        strcat(str_array, "TF_FASTOPEN | ");
    }
}

/* There are totally 23 values for t_flags2. So assume the caller has provided a
 * large enough array to hold 23 x sizeof("TF2_PROC_SACK_PROHIBIT |") == 552
 * bytes.
 */
void
translate_tflags2(uint32_t flags, char str_array[], size_t arr_size)
{
    assert(arr_size >= (23 * sizeof("TF2_PROC_SACK_PROHIBIT")));

    if (flags == 0) {
        strcat(str_array, "N/A");
        return;
    }

    if (flags & TF2_PLPMTU_BLACKHOLE) {
        strcat(str_array, "TF2_PLPMTU_BLACKHOLE | ");
    }
    if (flags & TF2_PLPMTU_PMTUD) {
        strcat(str_array, "TF2_PLPMTU_PMTUD | ");
    }
    if (flags & TF2_PLPMTU_MAXSEGSNT) {
        strcat(str_array, "TF2_PLPMTU_MAXSEGSNT | ");
    }
    if (flags & TF2_LOG_AUTO) {
        strcat(str_array, "TF2_LOG_AUTO | ");
    }
    if (flags & TF2_DROP_AF_DATA) {
        strcat(str_array, "TF2_DROP_AF_DATA | ");
    }
    if (flags & TF2_ECN_PERMIT) {
        strcat(str_array, "TF2_ECN_PERMIT | ");
    }
    if (flags & TF2_ECN_SND_CWR) {
        strcat(str_array, "TF2_ECN_SND_CWR | ");
    }
    if (flags & TF2_ECN_SND_ECE) {
        strcat(str_array, "TF2_ECN_SND_ECE | ");
    }
    if (flags & TF2_ACE_PERMIT) {
        strcat(str_array, "TF2_ACE_PERMIT | ");
    }
    if (flags & TF2_HPTS_CPU_SET) {
        strcat(str_array, "TF2_HPTS_CPU_SET | ");
    }
    if (flags & TF2_FBYTES_COMPLETE) {
        strcat(str_array, "TF2_FBYTES_COMPLETE | ");
    }
    if (flags & TF2_ECN_USE_ECT1) {
        strcat(str_array, "TF2_ECN_USE_ECT1 | ");
    }
    if (flags & TF2_TCP_ACCOUNTING) {
        strcat(str_array, "TF2_TCP_ACCOUNTING | ");
    }
    if (flags & TF2_HPTS_CALLS) {
        strcat(str_array, "TF2_HPTS_CALLS | ");
    }
    if (flags & TF2_MBUF_L_ACKS) {
        strcat(str_array, "TF2_MBUF_L_ACKS | ");
    }
    if (flags & TF2_MBUF_ACKCMP) {
        strcat(str_array, "TF2_MBUF_ACKCMP | ");
    }
    if (flags & TF2_SUPPORTS_MBUFQ) {
        strcat(str_array, "TF2_SUPPORTS_MBUFQ | ");
    }
    if (flags & TF2_MBUF_QUEUE_READY) {
        strcat(str_array, "TF2_MBUF_QUEUE_READY | ");
    }
    if (flags & TF2_DONT_SACK_QUEUE) {
        strcat(str_array, "TF2_DONT_SACK_QUEUE | ");
    }
    if (flags & TF2_CANNOT_DO_ECN) {
        strcat(str_array, "TF2_CANNOT_DO_ECN | ");
    }
    if (flags & TF2_PROC_SACK_PROHIBIT) {
        strcat(str_array, "TF2_PROC_SACK_PROHIBIT | ");
    }
    if (flags & TF2_IPSEC_TSO) {
        strcat(str_array, "TF2_IPSEC_TSO | ");
    }
    if (flags & TF2_NO_ISS_CHECK) {
        strcat(str_array, "TF2_NO_ISS_CHECK | ");
    }
}

void
print_cwd(void)
{
    char cwd[1024];
    if (getcwd(cwd, sizeof(cwd)) == NULL) {
        PERROR_FUNCTION("getcwd() error");
    } else {
        printf("Current working directory:\n %s\n", cwd);
    }
}

long int
my_atol(const char *str)
{
    char *endptr;
    long int number;
    errno = 0;  // To distinguish success/failure after the call
    number = strtol(str, &endptr, 10);

    // Check for conversion errors
    if (errno == ERANGE) {
        PERROR_FUNCTION("The number is out of range for a long integer.");
    } else if (str == endptr) {
        PERROR_FUNCTION("No digits were found in the string.");
    } else if (*endptr != '\0') {
        printf("Converted number: %ld\n", number);
        printf("Remaining string after number: \"%s\"\n", endptr);
        PERROR_FUNCTION("Partial digits from the string");
    }

    return number;
}

void
fill_flow_info(struct flow_info *target_flow, char *fields[])
{
    if (target_flow != NULL) {
        target_flow->flowid = (uint32_t)my_atol(fields[FL_FLOW_ID]);
        strcpy(target_flow->laddr, fields[FL_LOIP]);
        target_flow->lport = (uint16_t)my_atol(fields[FL_LPORT]);
        strcpy(target_flow->faddr, fields[FL_FOIP]);
        target_flow->fport = (uint16_t)my_atol(fields[FL_FPORT]);
        target_flow->ipver = INP_IPV4;
        target_flow->mss = (uint32_t)my_atol(fields[FL_MSS]);
        target_flow->isSACK = (bool)my_atol(fields[FL_ISSACK]);
        target_flow->snd_scale = (uint8_t)my_atol(fields[FL_SNDSCALE]);
        target_flow->rcv_scale = (uint8_t)my_atol(fields[FL_RCVSCALE]);
        target_flow->record_cnt = (uint32_t)my_atol(fields[FL_NUMRECORD]);
        target_flow->dir_in = 0;
        target_flow->dir_out = 0;
        target_flow->is_info_set = true;
    }
}

void
timeval_subtract(struct timeval *result, const struct timeval *t1,
                 const struct timeval *t2)
{
    result->tv_sec = t1->tv_sec - t2->tv_sec;
    result->tv_usec = t1->tv_usec - t2->tv_usec;

    // Handle underflow in microseconds
    if (result->tv_usec < 0) {
        result->tv_sec -= 1;
        result->tv_usec += 1000000;
    }
}

static inline bool
is_timeval_set(const struct timeval *val)
{
    return (val->tv_sec != 0 || val->tv_usec != 0);
}

char*
next_sub_str_from(char *str, const char *restrict delimiter)
{
    char *str1 = NULL;
    char *str2 = NULL;

    str1 = strtok(str, delimiter);
    str2 = strtok(NULL, delimiter);

    if (str1 == NULL || str2 == NULL) {
        PERROR_FUNCTION("Invalid input string.");
    }

    return str2;
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
        strcpy(f_line_stats->siftrver, next_sub_str_from(fields[SIFTRVER],
                                                            EQUAL_DELIMITER));
        strcpy(f_line_stats->sysname, next_sub_str_from(fields[SYSNAME],
                                                           EQUAL_DELIMITER));
        strcpy(f_line_stats->sysver, next_sub_str_from(fields[SYSVER],
                                                          EQUAL_DELIMITER));
        strcpy(f_line_stats->ipmode, next_sub_str_from(fields[IPMODE],
                                                          EQUAL_DELIMITER));

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
               "flow_list: %s\n\n",
               (long)l_line_stats->disable_time.tv_sec,
               (long)l_line_stats->disable_time.tv_usec,
               l_line_stats->global_flow_cnt,
               l_line_stats->max_tmp_qsize,
               l_line_stats->avg_tmp_qsize,
               l_line_stats->max_str_size,
               l_line_stats->alq_getn_fail_cnt,
               l_line_stats->flow_list_str);
    }

    f_basics->last_line_stats = l_line_stats;
}

static void
print_flow_info(struct flow_info *flow_info)
{
    printf(" id:%10u (%s:%hu<->%s:%hu) mss:%u SACK:%d snd/rcv_scal:%hhu/%hhu "
           "cnt:%u\n",
           flow_info->flowid,
           flow_info->laddr, flow_info->lport,
           flow_info->faddr, flow_info->fport,
           flow_info->mss,flow_info->isSACK,
           flow_info->snd_scale,flow_info->rcv_scale,
           flow_info->record_cnt);
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

    printf("starting_time: %jd.%06ld\n",
           f_basics->first_line_stats->enable_time.tv_sec,
           (intmax_t)f_basics->first_line_stats->enable_time.tv_usec);

    printf("ending_time: %jd.%06ld\n",
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
        snprintf(plot_file_name, MAX_NAME_LENGTH, "plot_%u.txt", flowid);
        printf("plot_file_name: %s\n", plot_file_name);

        printf("++++++++++++++++++++++++++++++ summary ++++++++++++++++++++++++++++\n");
        printf("  %s:%hu->%s:%hu flowid: %u\n",
               f_basics->flow_list[idx].laddr, f_basics->flow_list[idx].lport,
               f_basics->flow_list[idx].faddr, f_basics->flow_list[idx].fport,
               flowid);
        stats_into_plot_file(f_basics, flowid, plot_file_name);

        printf("    has %u useful records (%u outputs, %u inputs)\n",
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
