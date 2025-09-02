/*
 * lib.h
 *
 *  Created on: May 1, 2025
 *      Author: cc
 */

#ifndef LIB_H_
#define LIB_H_

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

#define GET_VALUE(field)    my_atol(next_sub_str_from(field, EQUAL_DELIMITER), BASE10);

typedef uint32_t tcp_seq;

enum {
    INP_IPV4 = 0x1,     // siftr2 is IPv4 only
    EIGHT_BYTES_LEN = 8,
    BASE10          = 10,
    BASE16          = 16,
    MAX_LINE_LENGTH = 1000,
    MAX_NAME_LENGTH = 100,
    INET6_ADDRSTRLEN = 46,
    TF_ARRAY_MAX_LENGTH = 550,
    TF2_ARRAY_MAX_LENGTH = 560,
    PER_FLOW_STRING_LENGTH = (INET6_ADDRSTRLEN*2 + 5*2 + 1),
    QUEUE_SIZE = 102400,
    QUEUE_MASK = QUEUE_SIZE - 1,
};

// siftr2 log header
struct first_line_fields {
    char        siftrver[EIGHT_BYTES_LEN];
    char        sysname[EIGHT_BYTES_LEN];
    char        sysver[EIGHT_BYTES_LEN];
    char        ipmode[EIGHT_BYTES_LEN];
    struct timeval enable_time;
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
my_atol(const char *str, int base)
{
    char *endptr;
    long int number;
    errno = 0;  // To distinguish success/failure after the call
    number = strtol(str, &endptr, base);

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

#endif /* LIB_H_ */
