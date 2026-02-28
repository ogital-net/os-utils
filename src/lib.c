
#include <stdint.h>
#include <sys/types.h>
#include <time.h>

#if defined(__APPLE__) && defined(__MACH__)
#include <mach/mach.h>
#include <mach/task_info.h>
#include <sys/sysctl.h>
#include <unistd.h>

uint64_t uptime_sys_c(void)
{
    return clock_gettime_nsec_np(CLOCK_MONOTONIC_RAW);
}

uint64_t uptime_proc_c(pid_t pid)
{
    struct kinfo_proc proc_info;
    size_t size = sizeof(proc_info);
    int32_t mib[4];
    struct timespec current_time;
    uint64_t currrent_nanos, proc_nanos;

    mib[0] = CTL_KERN;
    mib[1] = KERN_PROC;
    mib[2] = KERN_PROC_PID;
    mib[3] = pid;

    if (sysctl(mib, 4, &proc_info, &size, NULL, 0) == -1)
    {
        return 0;
    }

    clock_gettime(CLOCK_MONOTONIC_RAW, &current_time);
    currrent_nanos = (uint64_t)current_time.tv_sec * 1000000000 + current_time.tv_nsec;
    proc_nanos = ((uint64_t)proc_info.kp_proc.p_starttime.tv_sec * 1000000 + proc_info.kp_proc.p_starttime.tv_usec) * 1000;

    return currrent_nanos - proc_nanos;
}

size_t rss_self_c(void)
{
    task_basic_info_data_t info;
    mach_msg_type_number_t info_count = TASK_BASIC_INFO_COUNT;

    if (task_info(mach_task_self(), TASK_BASIC_INFO, (task_info_t)&info, &info_count) != KERN_SUCCESS)
    {
        return 0;
    }

    return info.resident_size;
}

#elif defined(__linux__)
#define _XOPEN_SOURCE 700
#define _GNU_SOURCE

#include <limits.h>
#include <stdio.h>
#include <sys/stat.h>
#include <sys/sysinfo.h>
#include <sys/time.h>
#include <unistd.h>

uint64_t uptime_sys_c(void)
{
    struct timespec ut;

    clock_gettime(CLOCK_MONOTONIC, &ut);
    return (uint64_t)ut.tv_sec * 1000000000 + ut.tv_nsec;
}

uint64_t uptime_proc_c(pid_t pid)
{
    char path[PATH_MAX];
    struct stat sb;
    struct timespec current_time;
    uint64_t currrent_nanos, proc_nanos;

    snprintf(path, sizeof(path), "/proc/%d", pid);

    if (stat(path, &sb) == -1)
    {
        return 0;
    }
    clock_gettime(CLOCK_MONOTONIC, &current_time);
    currrent_nanos = (uint64_t)current_time.tv_sec * 1000000000 + current_time.tv_nsec;
    proc_nanos = (uint64_t)sb.st_ctim.tv_sec * 1000000000 + sb.st_ctim.tv_nsec;

    return currrent_nanos - proc_nanos;
}

size_t rss_self_c(void)
{
    FILE *fp;
    size_t rss_pages;
    long page_size;

    fp = fopen("/proc/self/statm", "r");
    if (fp == NULL)
    {
        return 0;
    }

    if (fscanf(fp, "%*u %zu", &rss_pages) != 1)
    {
        fclose(fp);
        return 0;
    }

    fclose(fp);

    page_size = sysconf(_SC_PAGESIZE);
    return rss_pages * page_size;
}
#endif
