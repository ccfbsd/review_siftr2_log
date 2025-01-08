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

bool verbose = false;

void
stats_into_plot_file(struct file_basic_stats *f_basics, uint32_t flowid,
                     char plot_file_name[])
{
    uint32_t line_cnt = 0;
    uint32_t max_line_len = f_basics->last_line_stats->line_len;
    char current_line[max_line_len];
    char previous_line[max_line_len] = {};

    double first_flow_start_time = 0;
    double relative_time_stamp = 0;

    uint32_t data_pkt_cnt = 0;
    uint32_t fragment_cnt = 0;

    int idx;

    if (!is_flowid_in_file(f_basics, flowid, &idx)) {
        printf("%s:%u: flow ID %u not found\n", __FUNCTION__, __LINE__, flowid);
        PERROR_FUNCTION("Failed to open sack plot file for writing");
        return;
    }
    assert((0 == f_basics->flow_list[idx].dir_in) &&
           (0 == f_basics->flow_list[idx].dir_out));

    memset(previous_line, 0, max_line_len);

    /* Restart seeking and go back to the beginning of the file */
    rewind(f_basics->file);

    /* Read and discard the first line */
    if(fgets(current_line, max_line_len, f_basics->file) == NULL) {
        PERROR_FUNCTION("Failed to read first line");
        return;
    }
    line_cnt++; // Increment line counter, now shall be at the 2nd line

    FILE *plot_file = fopen(plot_file_name, "w");
    if (!plot_file) {
        PERROR_FUNCTION("Failed to open plot_file_name for writing");
        return;
    }

    fprintf(plot_file,
            "##direction" TAB "relative_timestamp" TAB "cwnd" TAB
            "ssthresh" TAB "th_seq" TAB "th_ack" TAB "data_size"
            "\n");

    while (fgets(current_line, max_line_len, f_basics->file) != NULL) {
        if (previous_line[0] != '\0') {
            char *fields[TOTAL_FIELDS];

            fill_fields_from_line(fields, previous_line, BODY);

            if (first_flow_start_time == 0) {
                first_flow_start_time = atof(fields[TIMESTAMP]);
                relative_time_stamp = 0;
            } else {
                relative_time_stamp = atof(fields[TIMESTAMP]) - first_flow_start_time;
            }

            if (my_atol(fields[FLOW_ID]) == flowid) {
                uint32_t data_sz = (uint32_t)my_atol(fields[TCP_DATA_SZ]);

                if (strcmp(fields[DIRECTION], "o") == 0) {
                    f_basics->flow_list[idx].dir_out++;
                } else {
                    f_basics->flow_list[idx].dir_in++;
                }

                if (data_sz > 0) {
                    data_pkt_cnt++;
                }
                if ((data_sz % f_basics->flow_list[idx].mss) > 0) {
                    fragment_cnt++;
                }
                fprintf(plot_file, "%s" TAB "%.6f" TAB "%8s" TAB
                        "%10s" TAB "%10s" TAB "%10s" TAB "%4u"
                        "\n",
                        fields[DIRECTION], relative_time_stamp, fields[CWND],
                        fields[SSTHRESH], fields[TH_SEQ], fields[TH_ACK], data_sz);
            }
        }

        line_cnt++;
        /* Update the previous line to be the current line. */
        strcpy(previous_line, current_line);
    }

    if (fclose(plot_file) == EOF) {
        PERROR_FUNCTION("Failed to close plot_file");
    }

    f_basics->num_lines = line_cnt;

    printf("input file has total lines: %u\n"
           "input flow data_pkt_cnt: %u, fragment_cnt: %u, fragment_ratio: %.3f\n",
           line_cnt, data_pkt_cnt, fragment_cnt,
           (double)fragment_cnt / data_pkt_cnt);
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
        {"verbose", no_argument, 0, 'v'},
        {0, 0, 0, 0}
    };

    // Process command-line arguments
    while ((opt = getopt_long(argc, argv, "vhf:s:", long_opts, &opt_idx)) != -1) {
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
            case 's':
                opt_match = true;
                printf("input flow id is: %s", optarg);
                if (!f_opt_match) {
                    printf(", but no data file is given\n");
                    return EXIT_FAILURE;
                } else {
                    printf("\n");
                }
                read_body_by_flowid(&f_basics, my_atol(optarg));
                break;
            default:
                printf("Usage: %s [-v | -h] [-f file_name] [-s flow_id]\n", argv[0]);
                return EXIT_FAILURE;
        }
    }

    /* Handle case where no options are provided or non-option arguments */
    if (!opt_match) {
        printf("Un-expected argument!\n");
        printf("Usage: %s [-v | -h] [-f file_name] [-s flow_id]\n", argv[0]);
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
