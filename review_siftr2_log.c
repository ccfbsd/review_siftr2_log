/*
 ============================================================================
 Name        : review_siftr_log.c
 Author      : Cheng Cui
 Version     :
 Copyright   : see the LICENSE file
 Description : Check siftr log stats in C, Ansi-style
 ============================================================================
 */
#include "review_siftr2_log.h"
#include <getopt.h>
#include "threads_compat.h"

bool verbose = false;

typedef struct {
    char direction[2];
    double rel_time;
    char cwnd[11];
    char ssthresh[11];
    char srtt[7];
    char data_sz[5];
} record_t;

#define QUEUE_SIZE 1024

typedef struct {
    record_t buffer[QUEUE_SIZE];
    size_t head, tail;
    bool done;
    mtx_t mutex;
    cnd_t cond_nonempty;
    cnd_t cond_nonfull;
} queue_t;

void queue_init(queue_t *q) {
    q->head = q->tail = 0;
    q->done = false;
    mtx_init(&q->mutex, mtx_plain);
    cnd_init(&q->cond_nonempty);
    cnd_init(&q->cond_nonfull);
}

bool queue_push(queue_t *q, record_t *rec) {
    mtx_lock(&q->mutex);
    while (((q->tail + 1) % QUEUE_SIZE) == q->head) {
        cnd_wait(&q->cond_nonfull, &q->mutex);
    }
    q->buffer[q->tail] = *rec;
    q->tail = (q->tail + 1) % QUEUE_SIZE;
    cnd_signal(&q->cond_nonempty);
    mtx_unlock(&q->mutex);
    return true;
}

bool queue_pop(queue_t *q, record_t *rec) {
    mtx_lock(&q->mutex);
    while (q->head == q->tail && !q->done) {
        cnd_wait(&q->cond_nonempty, &q->mutex);
    }
    if (q->head == q->tail && q->done) {
        mtx_unlock(&q->mutex);
        return false;
    }
    *rec = q->buffer[q->head];
    q->head = (q->head + 1) % QUEUE_SIZE;
    cnd_signal(&q->cond_nonfull);
    mtx_unlock(&q->mutex);
    return true;
}

int reader_thread(void *arg) {
    struct {
        struct file_basic_stats *f_basics;
        uint32_t flowid;
        queue_t *queue;
    } *ctx = arg;

    char current_line[ctx->f_basics->last_line_stats->line_len];
    char previous_line[ctx->f_basics->last_line_stats->line_len] = {};
    double first_flow_start_time = ctx->f_basics->first_flow_start_time;

    rewind(ctx->f_basics->file);
    fgets(current_line, sizeof(current_line), ctx->f_basics->file); // skip header

    while (fgets(current_line, sizeof(current_line), ctx->f_basics->file)) {
        if (previous_line[0] != '\0') {
            char *fields[TOTAL_FIELDS];
            fill_fields_from_line(fields, previous_line, BODY);

            if (first_flow_start_time == 0) {
                first_flow_start_time = atof(fields[TIMESTAMP]);
            }
            double rel_time = atof(fields[TIMESTAMP]) - first_flow_start_time;

            if (my_atol(fields[FLOW_ID], BASE16) == ctx->flowid) {
                record_t rec;
                snprintf(rec.direction, sizeof(rec.direction), "%s", fields[DIRECTION]);
                rec.rel_time = rel_time;
                snprintf(rec.cwnd, sizeof(rec.cwnd), "%s", fields[CWND]);
                snprintf(rec.ssthresh, sizeof(rec.ssthresh), "%s", fields[SSTHRESH]);
                snprintf(rec.srtt, sizeof(rec.srtt), "%s", fields[SRTT]);
                snprintf(rec.data_sz, sizeof(rec.data_sz), "%s", fields[TCP_DATA_SZ]);
                queue_push(ctx->queue, &rec);
            }
        }
        strcpy(previous_line, current_line);
    }

    mtx_lock(&ctx->queue->mutex);
    ctx->queue->done = true;
    cnd_broadcast(&ctx->queue->cond_nonempty);
    mtx_unlock(&ctx->queue->mutex);

    return 0;
}

int writer_thread(void *arg) {
    struct {
        FILE *plot_file;
        queue_t *queue;
    } *ctx = arg;

    record_t rec;
    while (queue_pop(ctx->queue, &rec)) {
        fprintf(ctx->plot_file, "%s" TAB "%.6f" TAB "%8s" TAB
                "%10s" TAB "%6s" TAB "%4s\n",
                rec.direction, rec.rel_time, rec.cwnd,
                rec.ssthresh, rec.srtt, rec.data_sz);
    }
    return 0;
}

void stats_into_plot_file(struct file_basic_stats *f_basics, uint32_t flowid,
                          char plot_file_name[])
{
    int idx;
    if (!is_flowid_in_file(f_basics, flowid, &idx)) {
        fprintf(stderr, "flow ID %u not found\n", flowid);
        return;
    }

    FILE *plot_file = fopen(plot_file_name, "w");
    if (!plot_file) {
        perror("open plot file");
        return;
    }
    fprintf(plot_file, "##direction" TAB "relative_timestamp" TAB "cwnd" TAB
            "ssthresh" TAB "srtt" TAB "data_size\n");

    queue_t queue;
    queue_init(&queue);

    struct {
        struct file_basic_stats *f_basics;
        uint32_t flowid;
        queue_t *queue;
    } reader_ctx = {f_basics, flowid, &queue};

    struct {
        FILE *plot_file;
        queue_t *queue;
    } writer_ctx = {plot_file, &queue};

    thrd_t t_reader, t_writer;
    thrd_create(&t_reader, reader_thread, &reader_ctx);
    thrd_create(&t_writer, writer_thread, &writer_ctx);

    thrd_join(t_reader, NULL);
    thrd_join(t_writer, NULL);

    fclose(plot_file);
}

int main(int argc, char *argv[]) {
    /* Record the start time */
    struct timeval start, end;
    gettimeofday(&start, NULL);

    struct file_basic_stats f_basics = {};

    int opt;
    int opt_idx = 0;
    bool opt_match = false, f_opt_match = false;
    struct option long_opts[] = {
        {"help", no_argument, 0, 'h'},
        {"file", required_argument, 0, 'f'},
        {"stats", required_argument, 0, 's'},
        {"flow_start", required_argument, 0, 't'},
        {"verbose", no_argument, 0, 'v'},
        {0, 0, 0, 0}
    };

    // Process command-line arguments
    while ((opt = getopt_long(argc, argv, "vhf:t:p:s:", long_opts, &opt_idx)) != -1) {
        switch (opt) {
            case 'v':
                verbose = opt_match = true;
                printf("verbose mode enabled\n");
                break;
            case 'h':
                opt_match = true;
                printf("Usage: %s [options]\n", argv[0]);
                printf(" -h, --help          Display this help message\n");
                printf(" -f, --file          Get siftr log basics\n");
                printf(" -t, --flow_start Unix_timestamp  The start Unix time of the first flow\n");
                printf(" -s, --stats flowid  Get stats from flowid\n");
                printf(" -v, --verbose       Verbose mode\n");
                break;
            case 'f':
                f_opt_match = opt_match = true;
                printf("input file name: %s\n", optarg);
                if (get_file_basics(&f_basics, optarg) != EXIT_SUCCESS) {
                    PERROR_FUNCTION("get_file_basics() failed");
                    return EXIT_FAILURE;
                }
                show_file_basic_stats(&f_basics);
                break;
            case 't':
                opt_match = true;
                printf("Unix time of the first flow starting time from "
                       "input is: %s\n", optarg);
                f_basics.first_flow_start_time = atof(optarg);
                break;
            case 'p':
                opt_match = true;
                if (verbose) {
                    printf("The prefix for the flow's plot file is: %s\n", optarg);
                }
                snprintf(f_basics.prefix, sizeof(f_basics.prefix), "%s", optarg);
                break;
            case 's':
                opt_match = true;
                printf("input flow id is: %s", optarg);
                if (!f_opt_match) {
                    printf(", but no data file is given\n");
                    return EXIT_FAILURE;
                } else {
                    printf("\n");
                }
                read_body_by_flowid(&f_basics, my_atol(optarg, BASE16));
                break;
            default:
                printf("Usage: %s [-v | -h] [-f file_name] [-t flow_start] "
                       "[-p prefix] [-s flow_id]\n", argv[0]);
                return EXIT_FAILURE;
        }
    }

    /* Handle case where no options are provided or non-option arguments */
    if (!opt_match) {
        printf("Un-expected argument!\n");
        printf("Usage: %s [-v | -h] [-f file_name] [-t flow_start] [-p prefix] [-s flow_id]"
               "\n", argv[0]);
        return EXIT_FAILURE;
    }

    if (opt_match && !f_opt_match) {
        return EXIT_SUCCESS;
    }

    if (cleanup_file_basic_stats(&f_basics) != EXIT_SUCCESS) {
        PERROR_FUNCTION("terminate_file_basics() failed");
    }

    // Record the end time
    gettimeofday(&end, NULL);
    // Calculate the time taken in seconds and microseconds
    double seconds = (end.tv_sec - start.tv_sec);
    double micros = ((seconds * 1000000) + end.tv_usec) - (start.tv_usec);

    printf("\nthis program execution time: %.3f seconds\n", micros / 1000000.0);

    return EXIT_SUCCESS;
}
