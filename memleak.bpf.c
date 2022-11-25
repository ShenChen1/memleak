// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
#include <vmlinux.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "memleak.h"

extern int LINUX_KERNEL_VERSION __kconfig;

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, u64);
    __type(value, u64);
} sizes SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1000000);
    __type(key, u64);
    __type(value, struct alloc_info_t);
} allocs SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, u64);
    __type(value, u64);
} memptrs SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_STACK_TRACE);
    __uint(key_size, sizeof(u32));
} stack_traces SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, u64);
    __type(value, struct combined_alloc_info_t);
} combined_allocs SEC(".maps");

char LICENSE[] SEC("license") = "Dual BSD/GPL";

const volatile bool trace_all = false;
const volatile size_t min_size = 0;
const volatile size_t max_size = 1UL << 32;
const volatile int sample_rate = 1;
const volatile int stack_flags = 0;
const volatile bool wa_missing_free = false;
const volatile long page_size = 4096;

static inline void update_statistics_add(u64 stack_id, u64 sz)
{
    struct combined_alloc_info_t *existing_cinfo;
    struct combined_alloc_info_t cinfo = {0};
    existing_cinfo = bpf_map_lookup_elem(&combined_allocs, &stack_id);
    if (existing_cinfo != 0)
        cinfo = *existing_cinfo;
    cinfo.total_size += sz;
    cinfo.number_of_allocs += 1;
    bpf_map_update_elem(&combined_allocs, &stack_id, &cinfo, BPF_ANY);
}

static inline void update_statistics_del(u64 stack_id, u64 sz)
{
    struct combined_alloc_info_t *existing_cinfo;
    struct combined_alloc_info_t cinfo = {0};
    existing_cinfo = bpf_map_lookup_elem(&combined_allocs, &stack_id);
    if (existing_cinfo != 0)
        cinfo = *existing_cinfo;
    if (sz >= cinfo.total_size)
        cinfo.total_size = 0;
    else
        cinfo.total_size -= sz;
    if (cinfo.number_of_allocs > 0)
        cinfo.number_of_allocs -= 1;
    bpf_map_update_elem(&combined_allocs, &stack_id, &cinfo, BPF_ANY);
}

static inline int gen_alloc_enter(struct pt_regs *ctx, size_t size)
{
    if (min_size > 0 && size < min_size) {
        return 0;
    }
    if (max_size > 0 && size > max_size) {
        return 0;
    }
    if (sample_rate > 1) {
        u64 ts = bpf_ktime_get_ns();
        if (ts % sample_rate != 0)
            return 0;
    }
    u64 pid = bpf_get_current_pid_tgid();
    u64 size64 = size;
    bpf_map_update_elem(&sizes, &pid, &size64, BPF_ANY);
    if (trace_all)
        bpf_printk("alloc entered, size = %llu", size);
    return 0;
}

static inline int gen_alloc_exit2(struct pt_regs *ctx, u64 address)
{
    u64 pid = bpf_get_current_pid_tgid();
    u64 *size64 = bpf_map_lookup_elem(&sizes, &pid);
    struct alloc_info_t info = {0};
    if (size64 == 0)
        return 0;  // missed alloc entry
    info.size = *size64;
    bpf_map_delete_elem(&sizes, &pid);
    if (address != 0) {
        info.timestamp_ns = bpf_ktime_get_ns();
        info.stack_id = bpf_get_stackid(ctx, &stack_traces, stack_flags);
        bpf_map_update_elem(&allocs, &address, &info, BPF_ANY);
        update_statistics_add(info.stack_id, info.size);
    }
    if (trace_all) {
        bpf_printk("alloc exited, size = %llu, result = %llx",
                    info.size, address);
    }
    return 0;
}

static inline int gen_alloc_exit(struct pt_regs *ctx)
{
    return gen_alloc_exit2(ctx, PT_REGS_RC(ctx));
}

static inline int gen_free_enter(struct pt_regs *ctx, void *address)
{
    u64 addr = (u64)address;
    struct alloc_info_t *info = bpf_map_lookup_elem(&allocs, &addr);
    if (info == 0)
        return 0;
    bpf_map_delete_elem(&allocs, &addr);
    update_statistics_del(info->stack_id, info->size);
    if (trace_all) {
        bpf_printk("free entered, address = %llx, size = %llu",
                    addr, info->size);
    }
    return 0;
}

SEC("uprobe/malloc")
int BPF_KPROBE(uprobe_malloc, size_t size)
{
    return gen_alloc_enter(ctx, size);
}

SEC("uretprobe/malloc")
int BPF_KRETPROBE(uretprobe_malloc, void *ret)
{
    return gen_alloc_exit(ctx);
}

SEC("uprobe/free")
int BPF_KPROBE(uprobe_free, void *addr)
{
    return gen_free_enter(ctx, addr);
}

SEC("uprobe/calloc")
int BPF_KPROBE(uprobe_calloc, size_t nmemb, size_t size)
{
    return gen_alloc_enter(ctx, nmemb * size);
}

SEC("uretprobe/calloc")
int BPF_KRETPROBE(uretprobe_calloc, void *ret)
{
    return gen_alloc_exit(ctx);
}

SEC("uprobe/realloc")
int BPF_KPROBE(uprobe_realloc, void *ptr, size_t size)
{
    gen_free_enter(ctx, ptr);
    return gen_alloc_enter(ctx, size);
}

SEC("uretprobe/realloc")
int BPF_KRETPROBE(uretprobe_realloc, void *ret)
{
    return gen_alloc_exit(ctx);
}

SEC("uprobe/mmap")
int BPF_KPROBE(uprobe_mmap)
{
    size_t size = (size_t)PT_REGS_PARM2(ctx);
    return gen_alloc_enter(ctx, size);
}

SEC("uretprobe/mmap")
int BPF_KRETPROBE(uretprobe_mmap, void *ret)
{
    return gen_alloc_exit(ctx);
}

SEC("uprobe/munmap")
int BPF_KPROBE(uprobe_munmap, void *addr)
{
    return gen_free_enter(ctx, addr);
}

SEC("uprobe/posix_memalign")
int BPF_KPROBE(uprobe_posix_memalign, void **memptr, size_t alignment, size_t size)
{
    u64 memptr64 = (u64)(size_t)memptr;
    u64 pid = bpf_get_current_pid_tgid();
    bpf_map_update_elem(&memptrs, &pid, &memptr64, BPF_ANY);
    return gen_alloc_enter(ctx, size);
}

SEC("uretprobe/posix_memalign")
int BPF_KRETPROBE(uretprobe_posix_memalign, int ret)
{
    u64 pid = bpf_get_current_pid_tgid();
    u64 *memptr64 = bpf_map_lookup_elem(&memptrs, &pid);
    void *addr;
    if (memptr64 == 0)
        return 0;
    bpf_map_delete_elem(&memptrs, &pid);
    if (bpf_probe_read_user(&addr, sizeof(void*), (void*)(size_t)*memptr64))
        return 0;
    u64 addr64 = (u64)(size_t)addr;
    return gen_alloc_exit2(ctx, addr64);
}

SEC("uprobe/aligned_alloc")
int BPF_KPROBE(uprobe_aligned_alloc, size_t alignment, size_t size)
{
    return gen_alloc_enter(ctx, size);
}

SEC("uretprobe/aligned_alloc")
int BPF_KRETPROBE(uretprobe_aligned_alloc, void *ret)
{
    return gen_alloc_exit(ctx);
}

SEC("uprobe/valloc")
int BPF_KPROBE(uprobe_valloc, size_t size)
{
    return gen_alloc_enter(ctx, size);
}

SEC("uretprobe/valloc")
int BPF_KRETPROBE(uretprobe_valloc, void *ret)
{
    return gen_alloc_exit(ctx);
}

SEC("uprobe/memalign")
int BPF_KPROBE(uprobe_memalign, size_t alignment, size_t size)
{
    bpf_printk("memalign ENTRY: alignment = %lu size = %lu", alignment, size);
    return 0;
}

SEC("uretprobe/memalign")
int BPF_KRETPROBE(uretprobe_memalign, void *ret)
{
    return gen_alloc_exit(ctx);
}

SEC("uprobe/pvalloc")
int BPF_KPROBE(uprobe_pvalloc, size_t size)
{
    return gen_alloc_enter(ctx, size);
}

SEC("uretprobe/pvalloc")
int BPF_KRETPROBE(uretprobe_pvalloc, void *ret)
{
    return gen_alloc_exit(ctx);
}

SEC("tracepoint/kmem/kmalloc")
int tracepoint_kmalloc(void *__args)
{
    struct trace_event_raw_kmem_alloc {
        struct trace_entry ent;
        const void *ptr;
        size_t bytes_alloc;
    } __attribute__((preserve_access_index));

    struct trace_event_raw_kmem_alloc *args = __args;
    if (wa_missing_free)
        gen_free_enter((struct pt_regs *)args, (void *)BPF_CORE_READ(args, ptr));
    gen_alloc_enter((struct pt_regs *)args, BPF_CORE_READ(args, bytes_alloc));
    return gen_alloc_exit2((struct pt_regs *)args, (size_t)BPF_CORE_READ(args, ptr));
}

SEC("tracepoint/kmem/kmalloc_node")
int tracepoint_kmalloc_node(void *__args)
{
    struct trace_event_raw_kmem_alloc_node {
        struct trace_entry ent;
        const void *ptr;
        size_t bytes_alloc;
    } __attribute__((preserve_access_index));

    struct trace_event_raw_kmem_alloc_node *args = __args;
    if (wa_missing_free)
        gen_free_enter((struct pt_regs *)args, (void *)BPF_CORE_READ(args, ptr));
    gen_alloc_enter((struct pt_regs *)args, BPF_CORE_READ(args, bytes_alloc));
    return gen_alloc_exit2((struct pt_regs *)args, (size_t)BPF_CORE_READ(args, ptr));
}

SEC("tracepoint/kmem/kfree")
int tracepoint_kfree(void *__args)
{
    struct trace_event_raw_kmem_free {
        struct trace_entry ent;
        const void *ptr;
    } __attribute__((preserve_access_index));

    struct trace_event_raw_kfree {
        struct trace_entry ent;
        const void *ptr;
    } __attribute__((preserve_access_index));

    if (LINUX_KERNEL_VERSION > KERNEL_VERSION(5, 18, 0)) {
        struct trace_event_raw_kfree *args = __args;
        return gen_free_enter((struct pt_regs *)args, (void *)BPF_CORE_READ(args, ptr));
    } else {
        struct trace_event_raw_kmem_free *args = __args;
        return gen_free_enter((struct pt_regs *)args, (void *)BPF_CORE_READ(args, ptr));
    }
}

SEC("tracepoint/kmem/kmem_cache_alloc")
int tracepoint_kmem_cache_alloc(void *__args)
{
    struct trace_event_raw_kmem_alloc {
        struct trace_entry ent;
        const void *ptr;
        size_t bytes_alloc;
    } __attribute__((preserve_access_index));

    struct trace_event_raw_kmem_alloc *args = __args;
    if (wa_missing_free)
        gen_free_enter((struct pt_regs *)args, (void *)BPF_CORE_READ(args, ptr));
    gen_alloc_enter((struct pt_regs *)args, BPF_CORE_READ(args, bytes_alloc));
    return gen_alloc_exit2((struct pt_regs *)args, (size_t)BPF_CORE_READ(args, ptr));
}

SEC("tracepoint/kmem/kmem_cache_alloc_node")
int tracepoint_kmem_cache_alloc_node(void *__args)
{
    struct trace_event_raw_kmem_alloc_node {
        struct trace_entry ent;
        const void *ptr;
        size_t bytes_alloc;
    } __attribute__((preserve_access_index));

    struct trace_event_raw_kmem_alloc_node *args = __args;
    if (wa_missing_free)
        gen_free_enter((struct pt_regs *)args, (void *)BPF_CORE_READ(args, ptr));
    gen_alloc_enter((struct pt_regs *)args, BPF_CORE_READ(args, bytes_alloc));
    return gen_alloc_exit2((struct pt_regs *)args, (size_t)BPF_CORE_READ(args, ptr));
}

SEC("tracepoint/kmem/kmem_cache_free")
int tracepoint_kmem_cache_free(void *__args)
{
    struct trace_event_raw_kmem_free {
        struct trace_entry ent;
        const void *ptr;
    } __attribute__((preserve_access_index));

    struct trace_event_raw_kmem_cache_free {
        struct trace_entry ent;
        const void *ptr;
    } __attribute__((preserve_access_index));

    if (LINUX_KERNEL_VERSION > KERNEL_VERSION(5, 18, 0)) {
        struct trace_event_raw_kmem_cache_free *args = __args;
        return gen_free_enter((struct pt_regs *)args, (void *)BPF_CORE_READ(args, ptr));
    } else {
        struct trace_event_raw_kmem_free *args = __args;
        return gen_free_enter((struct pt_regs *)args, (void *)BPF_CORE_READ(args, ptr));
    }
}

SEC("tracepoint/kmem/mm_page_alloc")
int tracepoint_mm_page_alloc(void *__args)
{
    struct trace_event_raw_mm_page_alloc {
        struct trace_entry ent;
        long unsigned int pfn;
        unsigned int order;
    } __attribute__((preserve_access_index));

    struct trace_event_raw_mm_page_alloc *args = __args;
    gen_alloc_enter((struct pt_regs *)args, page_size << BPF_CORE_READ(args, order));
    return gen_alloc_exit2((struct pt_regs *)args, BPF_CORE_READ(args, pfn));
}

SEC("tracepoint/kmem/mm_page_free")
int tracepoint_mm_page_free(void *__args)
{
    struct trace_event_raw_mm_page_free {
        struct trace_entry ent;
        long unsigned int pfn;
    } __attribute__((preserve_access_index));

    struct trace_event_raw_mm_page_free *args = __args;
    return gen_free_enter((struct pt_regs *)args, (void *)BPF_CORE_READ(args, pfn));
}

SEC("tracepoint/percpu/percpu_alloc_percpu")
int tracepoint_percpu_alloc_percpu(void *__args)
{
    struct trace_event_raw_percpu_alloc_percpu {
        struct trace_entry ent;
        size_t size;
        void *ptr;
    } __attribute__((preserve_access_index));

    struct trace_event_raw_percpu_alloc_percpu *args = __args;
    gen_alloc_enter((struct pt_regs *)args, BPF_CORE_READ(args, size));
    return gen_alloc_exit2((struct pt_regs *)args, (size_t)BPF_CORE_READ(args, ptr));
}

SEC("tracepoint/percpu/percpu_free_percpu")
int tracepoint_percpu_free_percpu(void *__args)
{
    struct trace_event_raw_percpu_free_percpu {
        struct trace_entry ent;
        void *ptr;
    } __attribute__((preserve_access_index));

    struct trace_event_raw_percpu_free_percpu *args = __args;
    return gen_free_enter((struct pt_regs *)args, (void *)BPF_CORE_READ(args, ptr));
}