/*
   Copyright (C) Cfengine AS

   This file is part of Cfengine 3 - written and maintained by Cfengine AS.

   This program is free software; you can redistribute it and/or modify it
   under the terms of the GNU General Public License as published by the
   Free Software Foundation; version 3.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with this program; if not, write to the Free Software
  Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA

  To the extent this program is licensed as part of the Enterprise
  versions of Cfengine, the applicable Commerical Open Source License
  (COSL) may apply to this file if you as a licensee so wish it. See
  included file COSL.txt.
*/

#include "procps.h"
#include "procps_priv.h"
#include "proc_keyvalue.h"
#include <sys/sysinfo.h>
#include "string_lib.h"

#define PROCSTAT_MAX_SIZE 1024

typedef struct
{
    char state;
    int pid;
    int ppid;
    int pgrp;
    unsigned long int utime;
    unsigned long int stime;
    long int priority;
    unsigned long int vsize;
    char tty[32];
    long num_thread;
    unsigned long starttime;
} ProcStat;

typedef struct
{
    char name[32];
    int real_uid;
    long int vm_rss;
} ProcStatus;

typedef struct
{
    char *command;
    char *args;
} ProcCmdLine;

static ProcStat *ReadStat(int pid);
static ProcCmdLine *ReadCmdLine(int pid);
static ProcCmdLine *StripCmdLine(char* buffer, size_t buffer_size);
static ProcStatus *ReadStatus(int pid);
static long int ReadMemory(void);
static void GetTime(unsigned long utime, unsigned long stime, char *buffer, int bufsize);
static void GetStartTime(unsigned long starttime, char *buffer, int bufsize);
static void GetTtyName(int tty_nr, char *buf, int bufsize);
static void TimeToString(unsigned long t, char *buffer, int bufsize);

ProcInfo *CollectProcInfo(void);
static char* ReadProcForPid(int pid);

static void GetTtyName(int tty_nr, char *buf, int bufsize)
{
    struct stat sbuf;
    int ttymajor = ((unsigned)tty_nr >> 8u) & 0xfffu;
    int ttyminor = ((unsigned)tty_nr & 0xffu) | (((unsigned)tty_nr&0xfff00000u)>>12u);
    char drivername[128] = {0};

    if (ttymajor)
    {
        FILE * fp = fopen("/proc/tty/drivers", "r");
        char range[32] = {0};
        int maj = 0;
      
        while (!feof(fp))
        {
            fscanf(fp, "%*s %s %d %s %*s", drivername, &maj, range);
            int min = 0, max = -1;
            sscanf(range, "%d-%d", &min, &max);
        
            if (maj == ttymajor)
            {
                if (ttyminor >= min && ttyminor <= max)
                {
                    break;
                }
                else if (max == -1 && ttyminor == min)
                {
                    break;
                }
            }
       }

        fclose(fp);

        if (stat(drivername, &sbuf) < 0)
        {
            snprintf(buf, bufsize, "?");
            return;
        }

    if (strstr(drivername, "pts"))
    {
        snprintf(buf, bufsize, "pts/%d", ttyminor);
        return;
    }

    char *retval = strrchr(drivername, '/');
    snprintf(buf, bufsize, "%s%d", ++retval, ttyminor);
    }
    else
    {
    snprintf(buf, bufsize, "?");
    }
}

static void TimeToString(unsigned long t, char *buffer, int bufsize)
{
    unsigned dd = 0, hh = 0, mm = 0, ss = 0;

    ss = t%60;
    t /= 60;
    mm = t%60;
    t /= 60;
    hh = t%24;
    t /= 24;
    dd = t;
    
    char *retval = buffer;
    retval += (dd ? snprintf(retval, bufsize, "%u-", dd)  : 0);
    retval += ( (dd || hh) ? snprintf(retval, bufsize, "%02u:", hh) : 0);
    retval += snprintf(retval, bufsize, "%02u:%02u", mm, ss);
}

static void GetStartTime(unsigned long starttime, char *buffer, int bufsize)
{
    unsigned long t;
    struct sysinfo info;
    
    if (!sysinfo(&info))
    {
        t = info.uptime - (unsigned long)(starttime / sysconf(_SC_CLK_TCK));
        TimeToString(t, buffer, bufsize);
    }
    else
    {
        snprintf(buffer, bufsize, "0-00:00:00");
    }
}

static void GetTime(unsigned long utime, unsigned long stime, char *buffer, int bufsize)
{
    unsigned long t;
    
    t = (unsigned long)((utime + stime) / sysconf(_SC_CLK_TCK));
    TimeToString(t, buffer, bufsize);
}

static char *ReadUserName(int uid)
{
    struct passwd *pwd = getpwuid(uid);

    char *s;
    /* Copying ps(1) semantics */
    if (pwd != NULL || strlen(pwd->pw_name) <= 12)
    {
        xasprintf(&s, "%s", pwd->pw_name);
    }
    else
    {
        xasprintf(&s, "%d", uid);
    }
    return s;
}


bool MemoryCallback(const char *field, off_t value, void *param)
{
    if (strcmp(field, "MemTotal") == 0)
    {
        long int *memsize = param;
        *memsize = value;
    }
    
    return true;
}


static long int ReadMemory()
{
    FILE *fh = fopen("/proc/meminfo", "r");
    
    if (fh != NULL)
    {
        long int memsize;
        if (ParseKeyNumericValue(fh, MemoryCallback, &memsize))
        {
            return memsize;
        }
    }
    
    return -1;
}


bool StatusCallback(const char *field, const char *value, void *param)
{
    ProcStatus *status = param;

    if (strcmp(field, "Name") == 0)
    {
        sscanf(value, "%s", status->name);
    }
    else if (strcmp(field, "Uid") == 0)
    {
        sscanf(value, "%d", &status->real_uid);
    }
    else if (strcmp(field, "VmRSS") == 0)
    {
        sscanf(value, "%ld", &status->vm_rss);
    }

return true;
}


static ProcStatus* ReadStatus(int pid)
{
    char path[1024];
    snprintf(path,1024,"/proc/%i/status",pid);

    FILE *fh = fopen(path, "r");

    if (fh != NULL)
    {
        ProcStatus* status = xcalloc(1, sizeof(ProcStatus));
        if (ParseKeyValue(fh, &StatusCallback, status))
        {
            fclose(fh);
            return status;
        }
        else
        {
            free(status);
        }
    }
    
    fclose(fh);
    return NULL;
}


/*
 * buffer should have one more zero byte after buffer_size.
 */

static ProcCmdLine *StripCmdLine(char* buffer, size_t buffer_size)
{
    /* [buffer..cmdend) is the command name */
    char *cmdend = memchr(buffer, '\0', buffer_size);

    if (cmdend == NULL)
    {
        /* buffer is empty -- e.g. unable to read from /proc due to permission
         * problems.
         */
        return NULL;
    }
    /* [argsstart..buffer+buffer_size) is the command args */
    char *argsstart = cmdend + 1;
    /* Convert those to human-readable form */
    char *p = argsstart;
    while ((p = memchr(p, '\0', buffer + buffer_size - p)))
    {
        *p = ' ';
    }

    ProcCmdLine *c = xmalloc(sizeof(ProcCmdLine));
    c->command = buffer;
    c->args = argsstart;
    return c;
}

static ProcCmdLine* ReadCmdLine(int pid)
{
    char path[CF_BUFSIZE];
    snprintf(path, CF_BUFSIZE, "/proc/%d/cmdline", pid);

    FILE *fh = fopen(path, "r");
    
    if (fh == NULL)
    {
        return NULL;
    }

    char buffer[CF_BUFSIZE] = "";
    ssize_t bytesread = fread(buffer, 1, CF_BUFSIZE-1, fh);
    
    if (ferror(fh))
    {
        fclose(fh);
        return NULL;
    }
    fclose(fh);

    return StripCmdLine(buffer, bytesread);
}


static ProcStat* ReadStat(int pid)
{
    char path[CF_BUFSIZE];
    snprintf(path, CF_BUFSIZE, "/proc/%d/stat", pid);

    FILE *fh = fopen(path, "r");

    if (fh == NULL)
    {
        return NULL;
    }

    ProcStat *stat = xcalloc(1,sizeof(ProcStat));
    int tty_nr;
    fscanf(fh,
           "%d %*s %c %d" /* pid, command, state, ppid */
           "%d %*d %d %*d" /* pgid, session, tty_nr, tpgid */
           "%*u %*u %*u %*u" /* flags, minflt, cminflt, majflt */
           "%*u %lu %lu %*d" /* cmajflt, utime, stime, cutime */
           "%*d %ld %*d %ld" /* cstime priority nice num_threads */
           "%*d %lu %lu", /* itrealvalue, starttime, vsize */
           &stat->pid, &stat->state,&stat->ppid, &stat->pgrp, &tty_nr, &stat->utime,
           &stat->stime, &stat->priority,&stat->num_thread,&stat->starttime, &stat->vsize);
    fclose(fh);

    GetTtyName(tty_nr, stat->tty, sizeof(stat->tty));

    return stat;
}

char* ReadProcForPid(int pid)
{
    ProcStat *csstat;
    ProcStatus *csstatus;
    ProcCmdLine *cscmdline;
    char *csusername;
    double cspmem;

    long int memsize;
    double p;
    char *buffer = NULL;

    if (pid <= 0)
    {
        return NULL;
    }

    buffer = xcalloc(CF_BUFSIZE, sizeof(char));

    if ((memsize = ReadMemory()) == -1)
    {
        free(buffer);
        return NULL;
    }

    if ((csstat = ReadStat(pid)) == NULL)
    {
        return NULL;
    }

    if ((csstatus = ReadStatus(pid)) == NULL)
    {
        free(csstat);
        return NULL;
    }

    cscmdline = ReadCmdLine(pid);
    csusername = ReadUserName(csstatus->real_uid);
    p = csstatus->vm_rss;
    cspmem = 100 * ((double)p) / memsize;
    char cmdline[CF_BUFSIZE];
    
    if (cscmdline)
    {
        snprintf(cmdline, CF_BUFSIZE, "%s %s", cscmdline->command, cscmdline->args);
    }
    else
    {
        snprintf(cmdline, CF_BUFSIZE, "[%s]", csstatus->name);
    }

    char cstime[256] = {0};
    char csstarttime[256] = {0};
    GetTime(csstat->utime, csstat->stime, cstime, sizeof(cstime));
    GetStartTime(csstat->starttime, csstarttime, sizeof(csstarttime));
    snprintf(buffer, CF_BUFSIZE, "%-12s %-3c %-5i %-5i %-5i %-5.1lf %-6lu %-4ld %-4ld %-5ld %-6s %-6s %-6s %-256s",
             csusername, csstat->state, csstat->pid, csstat->ppid, csstat->pgrp, cspmem,
             (csstat->vsize/1024), csstat->priority, csstatus->vm_rss, csstat->num_thread,
             csstat->tty, csstarttime, cstime, cmdline);



    free(csusername);
    free(cscmdline);
    free(csstat);
    free(csstatus);

    return buffer;
}

ProcInfo *CollectProcInfo(void)
{
    DIR *dir = opendir("/proc");
    if (dir == NULL)
    {
        return NULL;
    }

    ProcInfo *head = NULL;
    struct dirent *ptr;
    while ((ptr = readdir(dir)) != NULL)
    {
        if (ptr->d_type == DT_DIR) /* Works for procfs */
        {
            if (strcmp(ptr->d_name, ".") != 0 && strcmp(ptr->d_name, "..") != 0)
            {
                if (IsNumber(ptr->d_name))
                {
		            int pid = atoi(ptr->d_name); 
		            char *line = ReadProcForPid(pid);
		            if (line == NULL)
		            {
			            continue;
                    }
                    else
                    {
          	            ProcInfo *p = xmalloc(sizeof(ProcInfo));
                        p->pid = pid;
                        p->line = line;
                        p->next = head;
                        head = p;
                    }
                }
            }
        }
    }
    
    closedir(dir);
    return head;
}

void FreeProcInfo(ProcInfo *info)
{
    if (info)
    {
        FreeProcInfo(info->next);
        free(info->line);
        free(info);
    }
}

static void FillProcHeader(Item **procdata)
{
    char vbuff[CF_BUFSIZE];
    snprintf(vbuff, CF_BUFSIZE, "%-12s %-4s %-5s %-5s %-5s %-5s %-6s %-4s %-4s %-5s %-5s %-6s %-6s %-256s", "USER", "STAT", "PID", "PPID",
            "PGID", "PMEM", "VSZ", "PRI", "RSS", "NLWP", "TTY", "STIME", "TIME", "COMMAND");
    AppendItem(procdata, vbuff, "");
}


bool CollectLinuxProcInfo(Item **procdata)
{
    ProcInfo *procinfo = CollectProcInfo();
    if (procinfo == NULL)
    {
        return false;
    }

    FillProcHeader(procdata);

    for (ProcInfo *p = procinfo; p; p = p->next)
    {
        AppendItem(procdata, p->line, "");
    }

    FreeProcInfo(procinfo);

    return true;
}
