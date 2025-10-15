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
    char line[MAX_LINE_LENGTH];
    double time_stamp;
    uint32_t cwnd;
    uint32_t srtt;
    uint32_t data_sz;

    uint64_t line_num = 0;

    /* Restart seeking and go back to the beginning of the file */
    rewind(f_basics->file);

    FILE *plot_file = fopen(plot_file_name, "w");
    if (!plot_file) {
        PERROR_FUNCTION("Failed to open plot_file_name for writing");
        return;
    }

    fprintf(plot_file,
            "##line_num" TAB "direction" TAB "relative_timestamp" TAB "cwnd" TAB
            "ssthresh" TAB "srtt" TAB "data_size"
            "\n");

    while (fgets(line, sizeof(line), f_basics->file) != NULL) {
        char *fields[TOTAL_FIELDS];

        fill_fields_from_line(fields, line, BODY);

        if (my_atol(fields[FLOW_ID], BASE16) == flowid) {
            time_stamp = atof(fields[TIMESTAMP]);
            cwnd = my_atol(fields[CWND], BASE10);
            srtt = my_atol(fields[SRTT], BASE10);
            data_sz = my_atol(fields[TCP_DATA_SZ], BASE10);

            fprintf(plot_file, "%10" PRIu64 TAB
                    "%s" TAB "%.6f" TAB "%8u" TAB "%10s" TAB "%6u" TAB "%5u\n",
                    ++line_num,
                    fields[DIRECTION], time_stamp, cwnd,
                    fields[SSTHRESH], srtt, data_sz);
        }
    }

    if (fclose(plot_file) == EOF) {
        PERROR_FUNCTION("Failed to close plot_file");
    }

    f_basics->num_lines = line_num;
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
                printf(" -t, --flow_start    The start Unix time of the first flow\n");
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
                    printf(", but no data file is given\n");
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
