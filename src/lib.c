
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
#include <stdlib.h>
#include <string.h>
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
    char path[64];
    char buf[4096];
    FILE *fp;
    char *lparen, *rparen;
    unsigned long long start_ticks;
    long sc_clk_tck;

    /* /proc/<pid>/stat: "pid (comm) state ppid ..."; field 22 is starttime in clock
     * ticks since boot. comm may contain spaces or ')', so split on the last ')'. */
    snprintf(path, sizeof(path), "/proc/%d/stat", (int)pid);
    fp = fopen(path, "r");
    if (fp == NULL)
    {
        return 0;
    }
    if (fgets(buf, sizeof(buf), fp) == NULL)
    {
        fclose(fp);
        return 0;
    }
    fclose(fp);

    rparen = strrchr(buf, ')');
    if (rparen == NULL)
    {
        return 0;
    }
    lparen = strchr(buf, '(');
    if (lparen == NULL || lparen > rparen)
    {
        return 0;
    }
    /* /proc/<pid>/stat: "pid (comm) state ppid ...". `rparen` ends field 2 (comm);
     * the first byte after it is the space between field 2 and field 3. Walk
     * forward, counting whitespace-separated fields, until we reach field 22
     * (starttime). After the loop, `p` is the first byte of the field value. */
    {
        char *p = rparen + 1;
        int field = 2;
        while (field < 22 && *p != '\0')
        {
            if (*p == ' ')
            {
                field++;
                if (field == 22)
                {
                    p++;
                    break;
                }
            }
            p++;
        }
        if (field != 22 || *p == '\0' || sscanf(p, "%llu", &start_ticks) != 1)
        {
            return 0;
        }
    }

    sc_clk_tck = sysconf(_SC_CLK_TCK);
    if (sc_clk_tck <= 0)
    {
        return 0;
    }

    /* System uptime in seconds from /proc/uptime (first whitespace-separated field). */
    {
        double uptime_secs = 0.0;
        fp = fopen("/proc/uptime", "r");
        if (fp == NULL)
        {
            return 0;
        }
        if (fscanf(fp, "%lf", &uptime_secs) != 1)
        {
            fclose(fp);
            return 0;
        }
        fclose(fp);
        /* uptime - start_ticks/CLK_TCK, expressed in nanoseconds. */
        return (uint64_t)((uptime_secs - (double)start_ticks / (double)sc_clk_tck) * 1e9);
    }
}

/* Returns the resident set size in bytes, or SIZE_MAX on error. The success
 * path produces at least _SC_PAGESIZE bytes (any running process has at
 * least one resident page from the kernel's own bookkeeping), so SIZE_MAX
 * is unambiguous as an error indicator. */
size_t rss_self_c(void)
{
    FILE *fp;
    size_t rss_pages;
    long page_size;

    fp = fopen("/proc/self/statm", "r");
    if (fp == NULL)
    {
        return SIZE_MAX;
    }

    if (fscanf(fp, "%*u %zu", &rss_pages) != 1)
    {
        fclose(fp);
        return SIZE_MAX;
    }

    fclose(fp);

    page_size = sysconf(_SC_PAGESIZE);
    if (page_size <= 0)
    {
        return SIZE_MAX;
    }
    return rss_pages * page_size;
}
#endif
