
#include <stdint.h>
#include <sys/types.h>
#include <time.h>

#if defined(__APPLE__) && defined(__MACH__)
#include <sys/sysctl.h>

uint64_t uptime_sys_c(void)
{
    return clock_gettime_nsec_np(CLOCK_MONOTONIC_RAW);
}

uint64_t uptime_proc_c(pid_t pid)
{
    struct kinfo_proc proc_info;
    size_t size = sizeof(proc_info);
    int32_t mib[4];
    struct timeval current_time;
    uint64_t currrent_nanos, proc_nanos;

    mib[0] = CTL_KERN;
    mib[1] = KERN_PROC;
    mib[2] = KERN_PROC_PID;
    mib[3] = pid;

    if (sysctl(mib, 4, &proc_info, &size, NULL, 0) == -1)
    {
        return 0;
    }

    gettimeofday(&current_time, NULL);
    currrent_nanos = ((uint64_t)current_time.tv_sec * 1000000 + current_time.tv_usec) * 1000;
    proc_nanos = ((uint64_t)proc_info.kp_proc.p_starttime.tv_sec * 1000000 + proc_info.kp_proc.p_starttime.tv_usec) * 1000;

    return currrent_nanos - proc_nanos;
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
    struct timeval current_time;
    uint64_t currrent_nanos, proc_nanos;

    snprintf(path, sizeof(path), "/proc/%d", pid);

    if (stat(path, &sb) == -1)
    {
        return 0;
    }
    gettimeofday(&current_time, NULL);
    currrent_nanos = ((uint64_t)current_time.tv_sec * 1000000 + current_time.tv_usec) * 1000;
    proc_nanos = (uint64_t)sb.st_ctim.tv_sec * 1000000000 + sb.st_ctim.tv_nsec;

    return currrent_nanos - proc_nanos;
}
#endif
