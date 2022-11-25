# memleak

`memleak` tool rewritten with `libbpf` in c language.

The original tool in python [here](https://github.com/iovisor/bcc/blob/master/tools/memleak.py).

## Dependencies

Required:

- libelf
- zlib

## How to build

### Initialize

```console
$ git clone --recurse-submodules https://github.com/ShenChen1/memleak.git
```

### Build

```console
$ make CROSS_COMPILE=aarch64-buildroot-linux-gnu- V=1
```

### Usage

```console
# ./memleak
Attaching to kernel allocators, Ctrl+C to quit.
[07:14:06] Top 10 stacks with outstanding allocations:
	104 bytes in 1 allocations from stack
		__traceiter_kmem_cache_alloc+0x68
		__traceiter_kmem_cache_alloc+0x68
		kmem_cache_alloc+0x280
		alloc_buffer_head+0x28
		alloc_page_buffers+0xe0
		__getblk_gfp+0x158
		jbd2_journal_get_descriptor_buffer+0x60
		journal_submit_commit_record+0x80
		jbd2_journal_commit_transaction+0x1150
		kjournald2+0xc8
		kthread+0xfc
		ret_from_fork+0x10
```

See [here](https://github.com/iovisor/bcc/blob/master/tools/memleak_example.txt)

### License

This work is dual-licensed under the GNU GPL v2.0 (only) license and the
BSD 2-clause license. You can choose between one of them if you use this work.

`SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)`
