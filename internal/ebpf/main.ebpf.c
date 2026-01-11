#include "vmlinux.h"
#include <asm-generic/errno-base.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define BUFFER_LENGTH 64
#define MAX_ENTRIES 10240

struct data_t {
  char process_name[BUFFER_LENGTH];
  char filename[BUFFER_LENGTH];
  u32 uid;
  u32 pid;
};

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, MAX_ENTRIES);
  __type(key, u32);
  __type(value, struct data_t);
} datatable SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, MAX_ENTRIES);
  __type(key, char[BUFFER_LENGTH]);
  __type(value, u32);
} restricted_files SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, MAX_ENTRIES);
  __type(key, char[BUFFER_LENGTH]);
  __type(value, u32);
} restricted_directories SEC(".maps");

char LICENSE[] SEC("license") = "GPL";

SEC("tracepoint/syscalls/sys_enter_openat")
int trace_files(struct trace_event_raw_sys_enter *ctx) {
  u64 pid_tgid = bpf_get_current_pid_tgid();
  u32 pid = (u32)pid_tgid;
  struct data_t data = {};
  data.uid = (u32)bpf_get_current_uid_gid();
  data.pid = pid_tgid >> 32;
  char buffer[BUFFER_LENGTH];
  int is_command_name_available =
      bpf_get_current_comm(&data.process_name, sizeof(data.process_name)) == 0;
  int is_filename_available =
      bpf_probe_read_user_str(&data.filename, sizeof(data.filename),
                              (const char *)ctx->args[1]) >= 0;
  if (is_command_name_available && is_filename_available) {
    if (bpf_map_lookup_elem(&datatable, &pid) == NULL) {
      bpf_map_update_elem(&datatable, &pid, &data, BPF_ANY);
    }
  }
  return 0;
}

SEC("tracepoint/syscalls/sys_exit_openat")
int check_files(struct trace_event_raw_sys_exit *ctx) {
  u64 pid_tgid = bpf_get_current_pid_tgid();
  u32 pid = (u32)pid_tgid;
  if (ctx->ret >= 0) {
    return 0;
  } else {
    bpf_map_delete_elem(&datatable, &pid);
  }
  return 0;
}

SEC("lsm/file_open")
int BPF_PROG(restrict_file_access, struct file *file, int mask) {
  char name[BUFFER_LENGTH] = {0};
  if (bpf_d_path((struct path *)&file->f_path, name, sizeof(name)) < 0) {
    return 0;
  }
  char path[BUFFER_LENGTH] = {0};
  bpf_probe_read_kernel_str(&path, sizeof(path), name);
  if (bpf_map_lookup_elem(&restricted_files, &path) != NULL) {
    return -EACCES;
  }
  return 0;
}

SEC("lsm/path_unlink")
int BPF_PROG(restrict_file_deletion, const struct path *dir,
             struct dentry *dentry) {
  char parentpath[BUFFER_LENGTH] = {0};
  char name[BUFFER_LENGTH] = {0};

  bpf_d_path((struct path *)dir, name, sizeof(name));
  bpf_probe_read_kernel_str(&parentpath, sizeof(parentpath), name);
  if (bpf_map_lookup_elem(&restricted_directories, parentpath) != NULL) {
    return -EACCES;
  }
  return 0;
}
