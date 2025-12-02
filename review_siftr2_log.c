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
#include "threads_compat.h"

int reader_thread(void *arg) {
    struct {
        struct file_basic_stats *f_basics;
        uint32_t flowid;
        queue_t *queue;
    } *ctx = arg;

    const size_t line_len = ctx->f_basics->last_line_stats->line_len;
    char buf1[line_len];
    char buf2[line_len];
    char *cur_line = buf1;
    char *prev_line = buf2;
    bool have_prev = false;
    uint32_t start_time = ctx->f_basics->first_flow_start_time;

    char *fields[TOTAL_FIELDS];
    uint64_t line_cnt = 0;
    uint64_t num_records = 0;
    uint64_t yield_cnt = 0;
    record_t rec;

    rewind(ctx->f_basics->file);
    /* Read and discard the first line */
    if (fgets(cur_line, line_len, ctx->f_basics->file) == NULL) {
        PERROR_FUNCTION("Failed to read first line");
        return EXIT_FAILURE;
    }
    line_cnt++; // Increment line counter, now shall be at the 2nd line

    if (is_rec_fmt_binary) {
        struct pkt_node node;
        size_t rec_size = sizeof(struct pkt_node);

        while (true) {
            long pos = ftell(ctx->f_basics->file);
            if (pos < 0) {
                PERROR_FUNCTION("ftell");
                break;
            }
            if ((long)(pos + rec_size) > ctx->f_basics->last_line_offset) {
                // no more record: would cross into the footer — stop.
                break;
            }
            fread(&node, 1, rec_size, ctx->f_basics->file);

            if (node.flowid == ctx->flowid) {
                // Build record_t from node
                // Adjust field names and direction mapping to your definition
                rec.direction = (node.direction == DIR_IN) ? 'i' : 'o';
                rec.rel_time  = node.tval - start_time;
                rec.cwnd      = node.snd_cwnd;
                rec.ssthresh  = node.snd_ssthresh;
                rec.srtt      = node.srtt;
                rec.data_sz   = node.data_sz;

                // Push to queue (same backoff as before)
                while (!queue_push(ctx->queue, &rec)) {
                    yield_cnt++;
                    sched_yield();
                }
            }
            num_records++;
        }
    } else {
        line_cnt++; // Increment line counter, now shall be at the 2nd line
        while (fgets(cur_line, line_len, ctx->f_basics->file)) {
            if (have_prev && (fast_hex8_to_u32(prev_line) == ctx->flowid)) {
                fill_fields_from_line(fields, prev_line, BODY);

                rec.direction = *fields[DIRECTION];
                rec.rel_time = fast_hex_to_u32(fields[RELATIVE_TIME]) - start_time;
                rec.cwnd = fast_hex_to_u32(fields[CWND]);
                rec.ssthresh = fast_hex_to_u32(fields[SSTHRESH]);
                rec.srtt = fast_hex_to_u32(fields[SRTT]);
                rec.data_sz = fast_hex_to_u32(fields[TCP_DATA_SZ]);

                // Try to push; if full, yield briefly (lock-free backoff)
                while (!queue_push(ctx->queue, &rec)) {
                    yield_cnt++;
                    sched_yield(); // or nanosleep for gentler backoff
                }
            }
            line_cnt++;
            char *tmp = cur_line; cur_line = prev_line; prev_line = tmp;
            have_prev = true;
        }
    }

    // Signal completion
    queue_set_done(ctx->queue);

    ctx->f_basics->num_lines = line_cnt;
    ctx->f_basics->num_records = num_records;

    if (verbose) {
        printf("[%s] yield_cnt =  %" PRIu64 "\n", __FUNCTION__, yield_cnt);
    }

    return EXIT_SUCCESS;
}

int writer_thread(void *arg) {
    struct {
        struct file_basic_stats *f_basics;
        int idx;
        char *file_name;
        queue_t *queue;
    } *ctx = arg;

    uint64_t yield_cnt = 0;

    struct flow_info *f_info = &ctx->f_basics->flow_list[ctx->idx];

    FILE *plot_file = fopen(ctx->file_name, "w");
    if (!plot_file) {
        perror("open plot file");
        return EXIT_FAILURE;
    }

    // Allocate a large heap buffer for stdio
    const size_t large_buffer_size = 1u << 20;  // 1 MiB
    char *io_buffer = malloc(large_buffer_size);
    if (io_buffer) {
        // If malloc fails, stdio falls back to default internal buffering.
        // If setvbuf fails, we still proceed with default buffering,
        // but keep io_buffer allocated to free later for simplicity.
        setvbuf(plot_file, io_buffer, _IOFBF, large_buffer_size);
    }

    fprintf(plot_file,
            "##direction" TAB "relative_timestamp" TAB "cwnd" TAB "ssthresh" TAB
            "srtt" TAB "data_size\n");

    record_t rec;
    while (true) {
        if (queue_pop(ctx->queue, &rec)) {
            // update stats
            f_info->srtt_sum += rec.srtt;
            if (f_info->srtt_min > rec.srtt) {
                f_info->srtt_min = rec.srtt;
            }
            if (f_info->srtt_max < rec.srtt) {
                f_info->srtt_max = rec.srtt;
            }

            f_info->cwnd_sum += rec.cwnd;
            if (f_info->cwnd_min > rec.cwnd) {
                f_info->cwnd_min = rec.cwnd;
            }
            if (f_info->cwnd_max < rec.cwnd) {
                f_info->cwnd_max = rec.cwnd;
            }

            if (rec.data_sz > 0) {
                f_info->total_data_sz += rec.data_sz;
                f_info->data_pkt_cnt++;
                if (f_info->min_payload_sz > rec.data_sz) {
                    f_info->min_payload_sz = rec.data_sz;
                }
                if (f_info->max_payload_sz < rec.data_sz) {
                    f_info->max_payload_sz = rec.data_sz;
                }
            }
            if ((rec.data_sz % f_info->mss) > 0) {
                f_info->fragment_cnt++;
            }

            if (rec.direction == 'o') {
                f_info->dir_out++;
            } else {
                f_info->dir_in++;
            }

            fprintf(plot_file,
                    "%c" TAB "%.3f" TAB "%8u" TAB "%10u" TAB "%6u" TAB "%5u\n",
                    rec.direction, rec.rel_time / 1000.0f, rec.cwnd,
                    rec.ssthresh, rec.srtt, rec.data_sz);
        } else {
            if (queue_is_done(ctx->queue) && queue_is_empty(ctx->queue)) {
                break; // nothing left to consume
            }
            yield_cnt++;
            sched_yield(); // brief backoff when empty
        }
    }
    fflush(plot_file);
    fclose(plot_file);
    free(io_buffer); // only if you allocated it

    if (verbose) {
        printf("[%s] yield_cnt =  %" PRIu64 "\n", __FUNCTION__, yield_cnt);
    }

    return EXIT_SUCCESS;
}

void stats_into_plot_file(struct file_basic_stats *f_basics, uint32_t flowid,
                          char plot_file_name[])
{
    int idx;
    if (!is_flowid_in_file(f_basics, flowid, &idx)) {
        printf("%s:%u: flow id %u not found\n", __FUNCTION__, __LINE__, flowid);
        return;
    }

    queue_t queue;
    queue_init(&queue);

    struct {
        struct file_basic_stats *f_basics;
        uint32_t flowid;
        queue_t *queue;
    } reader_ctx = {f_basics, flowid, &queue};

    struct {
        struct file_basic_stats *f_basics;
        int idx;
        char *file_name;
        queue_t *queue;
    } writer_ctx = {f_basics, idx, plot_file_name, &queue};

    thrd_t t_reader, t_writer;
    thrd_create(&t_reader, reader_thread, &reader_ctx);
    thrd_create(&t_writer, writer_thread, &writer_ctx);

    thrd_join(t_reader, NULL);
    thrd_join(t_writer, NULL);
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

                if (!f_opt_match) {
                    printf("no data file is given\n");
                    return EXIT_FAILURE;
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
