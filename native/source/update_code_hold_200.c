/* Timed 1.99 return for this body's 2.01 to 2.00 MENU version check. */
#define _POSIX_C_SOURCE 200809L
#include <stdint.h>
#include <stddef.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/statfs.h>
#include <time.h>

enum {TMPFS_MAGIC=0x01021994,VERSION=1,HOLD_SECONDS=600};
enum {ST_CMD=1,ST_PRELOAD=2,ST_UNLINK=3,ST_PROC=4,ST_MAP=5,
      ST_MEM=6,ST_SIG=7,ST_FILE=8,ST_BASELINE=9,ST_WRITE=10,
      ST_RESTORE=11,ST_DONE=12,ST_ACTIVE=13,ST_FORK=14};
struct __attribute__((packed)) result {
    char magic[16];
    uint64_t lib_base;
    uint32_t version,stage,checks,pid,error;
    uint32_t before,during,after;
    uint16_t file_dat4,reserved;
    uint32_t crc;
};
_Static_assert(sizeof(struct result)==64,"update cache hold ABI");
static const char expected_cmdline[]=
    "/bin/sh\0-c\0/bin/date -s 070421422017.26";
static const char preload_path[]="/etc/ld.so.preload";
static const char preload_text[]="/tmp_wbshd/libcodex_update_code_hold200.so\n";
static const char start_path[]="/tmp_wbshd/codex_update_code_hold200_start.bin";
static const char done_path[]="/tmp_wbshd/codex_update_code_hold200_done.bin";
static const uint8_t signature[16]={
    0xfd,0x7b,0xbc,0xa9,0x01,0x00,0x80,0x52,
    0xfd,0x03,0x00,0x91,0xf5,0x13,0x00,0xf9};
static const uint64_t code_va=0x1888ULL;
static const uint32_t original=0x79407fa0u,spoofed=0x52803320u;
static const uint16_t installed_dat4=0x0201u;

static uint32_t crc32(const uint8_t *p,size_t n){
    uint32_t c=0xffffffffu;
    for(size_t i=0;i<n;++i){c^=p[i];
        for(unsigned j=0;j<8;++j)c=(c>>1)^(0xedb88320u&(0u-(c&1u)));}
    return c^0xffffffffu;
}
static void emit_to(const char *path,struct result *r){
    struct statfs fs={0};
    if(statfs("/tmp_wbshd",&fs)||fs.f_type!=TMPFS_MAGIC)return;
    int fd=open(path,O_WRONLY|O_CREAT|O_EXCL|O_CLOEXEC|O_NOFOLLOW,0600);
    if(fd<0)return;
    r->crc=0;r->crc=crc32((const uint8_t *)r,sizeof(*r));
    const uint8_t *p=(const uint8_t *)r;size_t left=sizeof(*r);
    while(left){ssize_t n=write(fd,p,left);if(n<=0)break;p+=n;left-=n;}
    if(!left)fsync(fd);close(fd);
}
static int find_im(void){
    DIR *d=opendir("/proc");if(!d)return -1;
    struct dirent *e;int found=-1;
    while((e=readdir(d))){
        char *end=0;long pid=strtol(e->d_name,&end,10);
        if(!end||*end||pid<=1||pid>100000)continue;
        char path[80],dest[256];
        if(snprintf(path,sizeof(path),"/proc/%ld/exe",pid)>=(int)sizeof(path))continue;
        ssize_t got=readlink(path,dest,sizeof(dest)-1);
        if(got<0||(size_t)got>=sizeof(dest))continue;
        dest[got]=0;
        if(strcmp(dest,"/usr/bin/im.elf")==0){
            if(found!=-1){found=-1;break;}found=(int)pid;}
    }
    closedir(d);return found;
}
static uint64_t find_base(int pid){
    char path[80],line[1024],name[512],perm[5];
    if(snprintf(path,sizeof(path),"/proc/%d/maps",pid)>=(int)sizeof(path))return 0;
    FILE *f=fopen(path,"r");if(!f)return 0;
    unsigned long long lo,hi,off;uint64_t base=0;unsigned count=0;
    while(fgets(line,sizeof(line),f)){
        name[0]=0;
        if(sscanf(line,"%llx-%llx %4s %llx %*s %*s %511s",
                  &lo,&hi,perm,&off,name)!=5)continue;
        if(lo<hi&&off==0&&strcmp(perm,"r-xp")==0&&
           strcmp(name,"/usr/lib/libupdaterufp.so")==0){base=lo;count++;}
    }
    fclose(f);return count==1?base:0;
}
static int read_at(int fd,uint64_t at,void *out,size_t size){
    return pread(fd,out,size,(off_t)at)==(ssize_t)size;
}
static int write_at(int fd,uint64_t at,const void *data,size_t size){
    return pwrite(fd,data,size,(off_t)at)==(ssize_t)size;
}
__attribute__((constructor))
static void begin(void){
    char cmd[sizeof(expected_cmdline)]={0};
    int fd=open("/proc/self/cmdline",O_RDONLY|O_CLOEXEC);
    if(fd<0)return;
    ssize_t n=read(fd,cmd,sizeof(cmd));close(fd);
    if(n!=(ssize_t)sizeof(cmd)||memcmp(cmd,expected_cmdline,sizeof(cmd)))return;
    struct result r={0};
    memcpy(r.magic,"A7C2UPCODE200",13);
    r.version=VERSION;r.pid=(uint32_t)getpid();r.stage=ST_CMD;r.checks|=1;
    char text[sizeof(preload_text)]={0};
    fd=open(preload_path,O_RDONLY|O_CLOEXEC|O_NOFOLLOW);
    if(fd<0){r.stage=ST_PRELOAD;emit_to(start_path,&r);_exit(0);}
    n=read(fd,text,sizeof(text));close(fd);
    if(n!=(ssize_t)sizeof(preload_text)-1||
       memcmp(text,preload_text,sizeof(preload_text)-1)){
        r.stage=ST_PRELOAD;emit_to(start_path,&r);_exit(0);}
    r.checks|=2;
    if(unlink(preload_path)){r.stage=ST_UNLINK;emit_to(start_path,&r);_exit(0);}
    r.checks|=4;
    int pid=find_im();
    if(pid<0){r.stage=ST_PROC;emit_to(start_path,&r);_exit(0);}
    r.pid=(uint32_t)pid;r.checks|=8;
    r.lib_base=find_base(pid);
    if(!r.lib_base){r.stage=ST_MAP;emit_to(start_path,&r);_exit(0);}
    r.checks|=16;
    char path[80];
    if(snprintf(path,sizeof(path),"/proc/%d/mem",pid)>=(int)sizeof(path)){
        r.stage=ST_MEM;emit_to(start_path,&r);_exit(0);}
    fd=open(path,O_RDWR|O_CLOEXEC);
    if(fd<0){r.stage=ST_MEM;emit_to(start_path,&r);_exit(0);}
    r.checks|=32;
    uint8_t got[sizeof(signature)]={0};
    if(!read_at(fd,r.lib_base+0x1824,got,sizeof(got))||
       memcmp(got,signature,sizeof(got))){
        r.stage=ST_SIG;close(fd);emit_to(start_path,&r);_exit(0);}
    r.checks|=64;
    int file=open("/setting/updater/dat4",O_RDONLY|O_CLOEXEC|O_NOFOLLOW);
    if(file<0){r.stage=ST_FILE;close(fd);emit_to(start_path,&r);_exit(0);}
    n=read(file,&r.file_dat4,2);close(file);
    if(n!=2||r.file_dat4!=installed_dat4){
        r.stage=ST_FILE;close(fd);emit_to(start_path,&r);_exit(0);}
    r.checks|=128;
    if(!read_at(fd,r.lib_base+code_va,&r.before,4)||r.before!=original){
        r.stage=ST_BASELINE;close(fd);emit_to(start_path,&r);_exit(0);}
    r.checks|=256;
    if(!write_at(fd,r.lib_base+code_va,&spoofed,4)||
       !read_at(fd,r.lib_base+code_va,&r.during,4)||r.during!=spoofed){
        r.stage=ST_WRITE;r.error=1;
        (void)write_at(fd,r.lib_base+code_va,&original,4);
        (void)read_at(fd,r.lib_base+code_va,&r.after,4);
        close(fd);emit_to(start_path,&r);_exit(0);}
    struct timespec deadline={0};
    if(clock_gettime(CLOCK_MONOTONIC,&deadline)){
        r.stage=ST_FORK;r.error=2;goto restore_now;}
    deadline.tv_sec+=HOLD_SECONDS;
    pid_t child=fork();
    if(child>0){
        r.stage=ST_ACTIVE;r.after=0xffffffffu;
        close(fd);emit_to(start_path,&r);_exit(0);}
    if(child==0){
        (void)setsid();
        for(int nfd=0;nfd<1024;++nfd)if(nfd!=fd)close(nfd);
        for(;;){
            struct timespec now={0};
            if(clock_gettime(CLOCK_MONOTONIC,&now)||now.tv_sec>=deadline.tv_sec)break;
            struct timespec rest={.tv_sec=1,.tv_nsec=0};
            (void)nanosleep(&rest,0);
        }
        r.stage=ST_DONE;r.error=0;
        if(!write_at(fd,r.lib_base+code_va,&original,4)||
           !read_at(fd,r.lib_base+code_va,&r.after,4)||r.after!=original){
            r.stage=ST_RESTORE;r.error=1;}
        else r.checks|=512;
        close(fd);emit_to(done_path,&r);_exit(0);
    }
    r.stage=ST_FORK;r.error=1;
restore_now:
    if(!write_at(fd,r.lib_base+code_va,&original,4)||
       !read_at(fd,r.lib_base+code_va,&r.after,4)||r.after!=original){
        r.stage=ST_RESTORE;r.error=2;}
    else r.checks|=512;
    close(fd);emit_to(start_path,&r);_exit(0);
}
