// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#include <argp.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>

#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <bpf/libbpf.h>

#include "memleak.h"
#include "memleak.skel.h"
#include "trace_helpers.h"
#include "uprobe_helpers.h"
#include "uthash.h"

static struct
{
    pid_t pid;
    bool trace_all;
    int interval;
    int count;
    bool show_allocs;
    uint64_t min_age_ns;
    char *command;
    bool combined_only;
    bool wa_missing_free;
    int sample_rate;
    int top;
    size_t min_size;
    size_t max_size;
    char *obj;
    bool percpu;
} env = {
    .pid = -1,
    .trace_all = false,
    .interval = 5,
    .count = 0,
    .show_allocs = false,
    .min_age_ns = 500 * 1e6,
    .command = NULL,
    .combined_only = false,
    .wa_missing_free = false,
    .sample_rate = 1,
    .top = 10,
    .min_size = 0,
    .max_size = 0,
    .obj = NULL,
    .percpu = false,
};

static const struct argp_option opts[] = {
    {"pid", 'p', "PID", 0, "Process PID"},
    {"trace", 't', NULL, 0, "Print trace message for each alloc/free call"},
    {"interval", ARGP_KEY_ARG, NULL, OPTION_DOC, "interval in seconds to print outstanding allocations"},
    {"count", ARGP_KEY_ARG, NULL, OPTION_DOC, "number of times to print the report before exiting"},
    {"show-allocs", 'a', NULL, 0, "show allocation addresses and sizes as well as call stacks"},
    {"older", 'o', "OLDER", 0, "prune allocations younger than this age in milliseconds"},
    {"command", 'c', "CMD", 0, "Execute and trace the specified command"},
    {"combined-only", 'C', NULL, 0, "show combined allocation statistics only"},
    {"wa-missing-free", 'w', NULL, 0, "Workaround to alleviate misjudgments when free is missing"},
    {"sample-rate", 's', "RATE", 0, "Sample every N-th allocation to decrease the overhead"},
    {"top", 'T', NULL, 0, "display only this many top allocating stacks (by size)"},
    {"min-size", 'z', NULL, 0, "Capture only allocations larger than this size"},
    {"max-size", 'Z', NULL, 0, "Capture only allocations smaller than this size"},
    {"obj", 'O', "OBJ", 0, "attach to allocator functions in the specified object"},
    {"percpu", 'P', NULL, 0, "Capture only allocations smaller than this size"},
    {0},
};

static error_t parse_opt(int key, char *arg, struct argp_state *state)
{
    switch (key) {
    case 'p': {
        pid_t pid = strtol(arg, NULL, 10);
        if (pid <= 0) {
            fprintf(stderr, "Invalid pid: %s\n", arg);
            argp_usage(state);
        }
        env.pid = pid;
        break;
    }
    case 't': {
        env.trace_all = true;
        break;
    }
    case 'a': {
        env.show_allocs = true;
        break;
    }
    case 'o': {
        int older = strtol(arg, NULL, 10);
        if (older <= 0) {
            fprintf(stderr, "Invalid older: %s\n", arg);
            argp_usage(state);
        }
        env.min_age_ns = 1e6 * older;
        break;
    }
    case 'c': {
        env.command = strdup(arg);
        break;
    }
    case 'C': {
        env.combined_only = true;
        break;
    }
    case 'W': {
        env.wa_missing_free = true;
        break;
    }
    case 's': {
        int sample_rate = strtol(arg, NULL, 10);
        if (sample_rate <= 0) {
            fprintf(stderr, "Invalid sample rate: %s\n", arg);
            argp_usage(state);
        }
        env.sample_rate = sample_rate;
        break;
    }
    case 'T': {
        int top = strtol(arg, NULL, 10);
        if (top <= 0) {
            fprintf(stderr, "Invalid top: %s\n", arg);
            argp_usage(state);
        }
        env.top = top;
        break;
    }
    case 'z': {
        size_t min_size = strtol(arg, NULL, 10);
        if (min_size <= 0) {
            fprintf(stderr, "Invalid min size: %s\n", arg);
            argp_usage(state);
        }
        env.min_size = min_size;
        break;
    }
    case 'Z': {
        size_t max_size = strtol(arg, NULL, 10);
        if (max_size <= 0) {
            fprintf(stderr, "Invalid max size: %s\n", arg);
            argp_usage(state);
        }
        env.max_size = max_size;
        break;
    }
    case 'O': {
        if (strlen(arg) > PATH_MAX) {
            fprintf(stderr, "object path too long\n");
            argp_usage(state);
        }
        env.obj = strdup(arg);
        break;
    }
    case 'P': {
        env.percpu = true;
        break;
    }
    case 'h': {
        argp_state_help(state, stderr, ARGP_HELP_STD_HELP);
        break;
    }
    case ARGP_KEY_ARG: {
        static int pos_args = 0;
        if (pos_args > 1) {
            fprintf(stderr, "Unrecognized positional argument: %s\n", arg);
            argp_usage(state);
        }
        if (pos_args == 0) {
            int interval = strtol(arg, NULL, 10);
            if (interval <= 0) {
                fprintf(stderr, "Invalid interval: %s\n", arg);
                argp_usage(state);
            }
            env.interval = interval;
        }
        if (pos_args == 1) {
            int count = strtol(arg, NULL, 10);
            if (count <= 0) {
                fprintf(stderr, "Invalid count: %s\n", arg);
                argp_usage(state);
            }
            env.count = count;
        }
        pos_args++;
        break;
    }
    default:
        return ARGP_ERR_UNKNOWN;
    }
    return 0;
}

const char argp_program_doc[] = "Trace and display outstanding allocations to detect\n"
                                "memory leaks in user-mode processes and the kernel.\n"
                                "\n"
                                "USAGE: memleak [-h] [-p PID] [-t] [-a] [-o OLDER] [-c COMMAND]\n"
                                "                [--combined-only] [--wa-missing-free] [-s SAMPLE_RATE]\n"
                                "                [-T TOP] [-z MIN_SIZE] [-Z MAX_SIZE] [-O OBJ]\n"
                                "                [interval] [count]\n"
                                "\n"
                                "EXAMPLES:\n"
                                "\n"
                                "./memleak -p $(pidof allocs)\n"
                                "        Trace allocations and display a summary of \"leaked\" (outstanding)\n"
                                "        allocations every 5 seconds\n"
                                "./memleak -p $(pidof allocs) -t\n"
                                "        Trace allocations and display each individual allocator function "
                                "call\n"
                                "./memleak -ap $(pidof allocs) 10\n"
                                "        Trace allocations and display allocated addresses, sizes, and stacks\n"
                                "        every 10 seconds for outstanding allocations\n"
                                "./memleak -c \"./allocs\"\n"
                                "        Run the specified command and trace its allocations\n"
                                "./memleak\n"
                                "        Trace allocations in kernel mode and display a summary of "
                                "outstanding\n"
                                "        allocations every 5 seconds\n"
                                "./memleak -o 60000\n"
                                "        Trace allocations in kernel mode and display a summary of "
                                "outstanding\n"
                                "        allocations that are at least one minute (60 seconds) old\n"
                                "./memleak -s 5\n"
                                "        Trace roughly every 5th allocation, to reduce overhead\n";

static const struct argp argp = {
    .options = opts,
    .parser = parse_opt,
    .doc = argp_program_doc,
};

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
    if (level == LIBBPF_DEBUG && !env.trace_all)
        return 0;
    return vfprintf(stderr, format, args);
}

void read_trace_pipe(void)
{
    int trace_fd = open("/sys/kernel/debug/tracing/trace_pipe", O_RDONLY, 0);
    if (trace_fd < 0)
        return;

    while (1) {
        static char buf[4096];
        ssize_t sz;

        sz = read(trace_fd, buf, sizeof(buf) - 1);
        if (sz > 0) {
            printf("%.*s", (int)sz, buf);
        }
    }
}

static int get_libc_path()
{
    FILE *f;
    char buf[PATH_MAX] = {};
    char *filename;
    float version;

    if (env.obj)
        return 0;

    f = fopen("/proc/self/maps", "r");
    if (!f)
        return -errno;

    while (fscanf(f, "%*x-%*x %*s %*s %*s %*s %[^\n]\n", buf) != EOF) {
        if (strchr(buf, '/') != buf)
            continue;
        filename = strrchr(buf, '/') + 1;
        if (sscanf(filename, "libc-%f.so", &version) == 1) {
            env.obj = strdup(buf);
            fclose(f);
            return 0;
        }
    }

    fclose(f);
    return -1;
}

static void sig_handler(int signo)
{
    if (env.pid <= 0)
        return;

    if (signo == SIGINT || signo == SIGTERM) {
        // kill all child processes forked by command
        kill(0, SIGKILL);
    }
}

static pid_t create_child_process(const char *command)
{
    int i = 0;
    const char *delim = " ";
    char *cmd = strdup(command);
    char **argv = NULL, *filepath = NULL;
    char *ptr = strtok(cmd, delim);
    if (ptr != NULL) {
        filepath = ptr;
        ptr = strtok(NULL, delim);
    } else {
        fprintf(stderr, "Failed to exec %s\n", command);
        exit(-1);
    }
    while (ptr != NULL) {
        argv = (char **)realloc(argv, sizeof(char *) * (i + 1));
        argv[i++] = ptr;
        ptr = strtok(NULL, delim);
    }

    pid_t pid = fork();
    if (pid == 0) {
        execve(filepath, argv, NULL);
        _exit(EXIT_FAILURE);
    } else if (pid > 0) {
        // main process
        signal(SIGINT, sig_handler);
    } else {
        fprintf(stderr, "Failed to exec %s\n", command);
        exit(-1);
    }

    return pid;
}

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

typedef struct {
    __u64 addr;
    struct alloc_info_t info;
} alloc_info_map_t;

static int alloc_info_compare(const void *l, const void *r)
{
    const alloc_info_map_t *left = l;
    const alloc_info_map_t *right = r;

    return left->info.size < right->info.size;
}

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

typedef struct {
    int stack_id; /* we'll use this field as the key */
    size_t size;
    size_t count;
    UT_hash_handle hh; /* makes this structure hashable */
} alloc_info_hash_t;

static alloc_info_hash_t *alloc_info = NULL;

static void hash_add_alloc_info(int stack_id, size_t size)
{
    alloc_info_hash_t *s = NULL;

    HASH_FIND_INT(alloc_info, &stack_id, s);
    if (s == NULL) {
        s = malloc(sizeof(alloc_info_hash_t));
        s->stack_id = stack_id;
        s->size = size;
        s->count = 1;
        HASH_ADD_INT(alloc_info, stack_id, s);
    } else {
        s->size += size;
        s->count += 1;
    }
}

static void hash_delete_all_alloc_info()
{
    alloc_info_hash_t *cur, *tmp;

    HASH_ITER(hh, alloc_info, cur, tmp) {
        HASH_DEL(alloc_info, cur);
        free(cur);
    }
}

static int by_size(const void *l, const void *r)
{
    const alloc_info_hash_t *left = l;
    const alloc_info_hash_t *right = r;

    return left->size > right->size;
}

static void hash_sort_alloc_info_by_size()
{
    HASH_SORT(alloc_info, by_size);
}

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

typedef struct {
    __u32 stack_id;
    struct combined_alloc_info_t info;
} combined_alloc_info_map_t;

static int combined_alloc_info_compare(const void *l, const void *r)
{
    const combined_alloc_info_map_t *left = l;
    const combined_alloc_info_map_t *right = r;

    return left->info.total_size > right->info.total_size;
}

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

static void print_user_stack(struct memleak_bpf *skel, struct syms_cache *syms_cache, __u32 stack_id)
{
    size_t cap = bpf_map__value_size(skel->maps.stack_traces);
    __u64 *uip = (void *)calloc(1, cap);
    if (uip == NULL) {
        fprintf(stderr, "Failed to calloc\n");
        return;
    }

    const struct syms *syms = syms_cache__get_syms(syms_cache, env.pid);
    if (!syms) {
        fprintf(stderr, "Failed to get syms\n");
        goto cleanup;
    }

    int err = bpf_map__lookup_elem(skel->maps.stack_traces, &stack_id, sizeof(__u32), uip, cap, 0);
    if (err < 0) {
        printf("\t\tstack information lost\n");
        goto cleanup;
    }

    cap /= sizeof(__u64);
    for (size_t j = 0; uip[j] && j < cap; j++) {
        char *dso_name;
        uint64_t dso_offset;
        const struct sym *sym = syms__map_addr_dso(syms, uip[j], &dso_name, &dso_offset);
        if (sym) {
            printf("\t\t%s+0x%lx", sym->name, sym->offset);
            if (dso_name)
                printf(" [%s]", dso_name);
            printf("\n");
        } else {
            printf("\t\t0x%lx\n", (uint64_t)uip[j]);
        }
    }

cleanup:
    free(uip);
}

static void print_outstanding(struct memleak_bpf *skel, struct syms_cache *syms_cache)
{
    time_t now;
    time(&now);
    struct tm *timeinfo = localtime(&now);
    printf("[%02x:%02d:%02d] Top %d stacks with outstanding allocations:\n", timeinfo->tm_hour, timeinfo->tm_min, timeinfo->tm_sec, env.top);

    size_t cap = bpf_map__max_entries(skel->maps.allocs);
    alloc_info_map_t *allocs = (void *)calloc(cap, sizeof(alloc_info_map_t));
    if (allocs == NULL) {
        fprintf(stderr, "Failed to calloc\n");
        return;
    }


    size_t cnt = 0;
    __u64 addr = 0, next_addr;
    while (!bpf_map__get_next_key(skel->maps.allocs, &addr, &next_addr, sizeof(__u64))) {
        struct alloc_info_t alloc = {};
        int err = bpf_map__lookup_elem(skel->maps.allocs, &next_addr, sizeof(__u64), &alloc, sizeof(struct alloc_info_t), 0);
        if (err < 0) {
            fprintf(stderr, "Failed to lookup allocs: %d\n", err);
            goto cleanup;
        }

        allocs[cnt].addr = next_addr;
        allocs[cnt].info = alloc;

        addr = next_addr;
        cnt++;
    }
    qsort(allocs, cnt, sizeof(alloc_info_map_t), alloc_info_compare);

    struct timespec monotime;
    clock_gettime(CLOCK_MONOTONIC, &monotime);
    uint64_t now_ns = monotime.tv_sec * 1e9 + monotime.tv_nsec;

    for (size_t i = 0; i < cnt; i++) {
        if (now_ns - env.min_age_ns < allocs[i].info.timestamp_ns) {
            continue;
        }

        if (!allocs[i].info.stack_id) {
            continue;
        }

        /* combine alloc info */
        hash_add_alloc_info(allocs[i].info.stack_id, allocs[i].info.size);

        if (env.show_allocs) {
            printf("\taddr = %lx size = %lu\n", (uint64_t)allocs[i].addr, (uint64_t)allocs[i].info.size);
        }
    }

    /* sort */
    hash_sort_alloc_info_by_size();

    size_t count = 0;
    for (alloc_info_hash_t *s = alloc_info; s != NULL; s = (s->hh.next)) {
        printf("\t%zu bytes in %zu allocations from stack\n", s->size, s->count);
        print_user_stack(skel, syms_cache, s->stack_id);

        if (count++ == env.top)
            break;
    }

    hash_delete_all_alloc_info();
cleanup:
    free(allocs);
}

static void print_outstanding_combined(struct memleak_bpf *skel, struct syms_cache *syms_cache)
{
    time_t now;
    time(&now);
    struct tm *timeinfo = localtime(&now);
    printf("[%02x:%02d:%02d] Top %d stacks with outstanding allocations:\n", timeinfo->tm_hour, timeinfo->tm_min, timeinfo->tm_sec, env.top);

    size_t cap = bpf_map__max_entries(skel->maps.combined_allocs);
    combined_alloc_info_map_t *stacks = (void *)calloc(cap, sizeof(combined_alloc_info_map_t));
    if (stacks == NULL) {
        fprintf(stderr, "Failed to calloc\n");
        return;
    }

    size_t cnt = 0;
    __u64 stack_id = 0, next_stack_id;
    while (!bpf_map__get_next_key(skel->maps.combined_allocs, stack_id ? &stack_id : NULL, &next_stack_id, sizeof(__u64))) {
        struct combined_alloc_info_t stack = {};
        int err = bpf_map__lookup_elem(skel->maps.combined_allocs, &next_stack_id, sizeof(__u64), &stack, sizeof(struct combined_alloc_info_t), 0);
        if (err < 0) {
            fprintf(stderr, "Failed to lookup stacks: %d\n", err);
            goto cleanup;
        }

        stacks[cnt].stack_id = next_stack_id;
        stacks[cnt].info = stack;

        stack_id = next_stack_id;
        cnt++;
    }
    qsort(stacks, cnt, sizeof(combined_alloc_info_map_t), combined_alloc_info_compare);

    for (size_t i = 0; i < cnt; i++) {
        printf("\t%llu bytes in %llu allocations from stack\n", stacks[i].info.total_size, stacks[i].info.number_of_allocs);
        print_user_stack(skel, syms_cache, stacks[i].stack_id);

        if (i == env.top)
            break;
    }

cleanup:
    free(stacks);
}

int main(int argc, char **argv)
{
    struct memleak_bpf *skel;
    int err;

    /* Parse command line args */
    err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
    if (err)
        return err;

    if (env.command != NULL) {
        printf("Executing '%s' and tracing the resulting process.\n", env.command);
        env.pid = create_child_process(env.command);
    }

    /* Set up libbpf errors and debug stacks callback */
    libbpf_set_print(libbpf_print_fn);
    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);

    /* Load BPF application */
    skel = memleak_bpf__open();
    if (!skel) {
        fprintf(stderr, "Failed to open BPF skeleton\n");
        return 1;
    }

    skel->rodata->sample_rate = env.sample_rate;
    skel->rodata->min_size = env.min_size;
    skel->rodata->max_size = env.max_size;
    skel->rodata->trace_all = env.trace_all;
    skel->rodata->stack_flags = BPF_F_USER_STACK;

    bpf_map__set_value_size(skel->maps.stack_traces, 127 * sizeof(__u64));
    bpf_map__set_max_entries(skel->maps.stack_traces, 10 * 1024);

    /* Load & verify BPF programs */
    err = memleak_bpf__load(skel);
    if (err) {
        fprintf(stderr, "Failed to load and verify BPF skeleton\n");
        goto cleanup;
    }

    struct syms_cache *syms_cache = syms_cache__new(0);
    if (!syms_cache) {
        fprintf(stderr, "failed to create syms_cache\n");
        goto cleanup;
    }

    err = get_libc_path();
    if (err) {
        fprintf(stderr, "could not find libc.so\n");
        goto cleanup;
    }

    printf("Attaching to pid %d, Ctrl+C to quit.\n", env.pid);
    INIT_UPROBE_URETPROBE(malloc, env.pid, env.obj, "malloc");
    INIT_UPROBE(free, env.pid, env.obj, "free");
    INIT_UPROBE_URETPROBE(calloc, env.pid, env.obj, "calloc");
    INIT_UPROBE_URETPROBE(realloc, env.pid, env.obj, "realloc");
    INIT_UPROBE_URETPROBE(mmap, env.pid, env.obj, "mmap");
    INIT_UPROBE(munmap, env.pid, env.obj, "munmap");
    INIT_UPROBE_URETPROBE(posix_memalign, env.pid, env.obj, "posix_memalign");
    INIT_UPROBE_URETPROBE(aligned_alloc, env.pid, env.obj, "aligned_alloc");
    INIT_UPROBE_URETPROBE(valloc, env.pid, env.obj, "valloc");
    INIT_UPROBE_URETPROBE(memalign, env.pid, env.obj, "memalign");
    INIT_UPROBE_URETPROBE(pvalloc, env.pid, env.obj, "pvalloc");

    /* Let libbpf perform auto-attach for uprobe/uretprobe
     * NOTICE: we provide path and symbol stacks in SEC for BPF programs
     */
    err = memleak_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to auto-attach BPF skeleton: %d\n", err);
        goto cleanup;
    }

    if (env.trace_all)
        read_trace_pipe();
    else {
        int count_so_far = 0;
        while (1) {
            sleep(env.interval);

            if (env.combined_only)
                print_outstanding_combined(skel, syms_cache);
            else
                print_outstanding(skel, syms_cache);

            count_so_far++;
            if (env.count && count_so_far >= env.count)
                break;
        }
    }

cleanup:
    if (skel)
        memleak_bpf__destroy(skel);
    if (syms_cache)
        syms_cache__free(syms_cache);
    return -err;
}