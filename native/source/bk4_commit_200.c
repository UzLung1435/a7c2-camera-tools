/* Persistent BK4 color-property file edit for this A7 C II body 2.00.
 * Validates both current files against the observed official 2.01 structure,
 * changes only property 0x02A40001 (8 KiB) and the second-record checksum,
 * and verifies each entire second BK4 record. On error, tries to restore both
 * files' exact old property and checksum. Does not touch CP RAM or firmware.
 */
#define _GNU_SOURCE
#include <stdint.h>
#include <stddef.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <limits.h>

#include "color_property_slots.h"

enum { TMPFS_MAGIC=0x01021994, SIZE=8192, FILE_SIZE=2390264,
       BK4_BASE=0xED000, BK4_END=0x2478F8, COLOR_OFFSET=0x1BBA4C,
       CHECKSUM_OFFSET=0xED020, TABLE_OFFSET=0x11D346,
       CHECKSUM_DELTA=19569 };
struct __attribute__((packed)) result {
    char magic[16];
    uint32_t version,stage,checks,pid,error,dat4;
    uint32_t old_checksum[2],new_checksum[2];
    int32_t validate[2],write_result[2],verify[2],emergency[2];
    uint32_t crc;
};
_Static_assert(sizeof(struct result)==92,"BK4 generic file marker ABI");
static const char expected_cmdline[]="/bin/sh\0-c\0/bin/date -s 070421422017.26";
static const char preload_path[]="/etc/ld.so.preload";
static const char preload_text[]="/tmp_wbshd/libcodex_cp_fl23_bk4_files_200.so\n";
static const char marker_path[]="/tmp_wbshd/codex_cp_fl23_bk4_files_200.bin";
static const char magic_text[]="A7C2BK4GEN200";
static const char *files[2]={"/setting/Backup.bin","/setting/Backup.bak"};
static unsigned char chunk[SIZE];

static uint32_t crc32(const uint8_t *p,size_t n){
    uint32_t c=0xffffffffu;
    for(size_t i=0;i<n;++i){c^=p[i];
        for(unsigned j=0;j<8;++j)c=(c>>1)^(0xedb88320u&(0u-(c&1u)));}
    return c^0xffffffffu;
}
static void emit(struct result *r){
    struct statfs fs={0};
    if(statfs("/tmp_wbshd",&fs)||fs.f_type!=TMPFS_MAGIC)return;
    int fd=open(marker_path,O_WRONLY|O_CREAT|O_EXCL|O_CLOEXEC|O_NOFOLLOW,0600);
    if(fd<0)return;
    r->crc=0;r->crc=crc32((const uint8_t *)r,sizeof(*r));
    const uint8_t *p=(const uint8_t *)r;size_t left=sizeof(*r);
    while(left){ssize_t n=write(fd,p,left);if(n<=0)break;p+=n;left-=n;}
    if(!left)fsync(fd);close(fd);
}
static int exact_child(void){
    char cmd[sizeof(expected_cmdline)]={0};
    int fd=open("/proc/self/cmdline",O_RDONLY|O_CLOEXEC);
    if(fd<0)return 0;
    ssize_t n=read(fd,cmd,sizeof(cmd));close(fd);
    return n==(ssize_t)sizeof(cmd) && !memcmp(cmd,expected_cmdline,sizeof(cmd));
}
static uint32_t le32(const unsigned char *p){
    return (uint32_t)p[0]|((uint32_t)p[1]<<8)|((uint32_t)p[2]<<16)|((uint32_t)p[3]<<24);
}
static int record_sum(int fd,uint32_t *out){
    uint64_t sum=0;
    for(off_t at=BK4_BASE;at<BK4_END;){
        size_t n=(size_t)(BK4_END-at);
        if(n>SIZE)n=SIZE;
        if(pread(fd,chunk,n,at)!=(ssize_t)n)return -1;
        for(size_t i=0;i<n;++i){
            off_t pos=at+(off_t)i;
            if(pos<CHECKSUM_OFFSET||pos>=CHECKSUM_OFFSET+4)sum+=chunk[i];
        }
        at+=(off_t)n;
    }
    *out=(uint32_t)sum;
    return 0;
}
static int validate_file(int fd,const unsigned char *value,
                         uint32_t expected_checksum,uint32_t *observed_checksum){
    struct stat st={0};
    if(fstat(fd,&st)||!S_ISREG(st.st_mode)||st.st_size!=FILE_SIZE)return -1;
    unsigned char h[64]={0};
    if(pread(fd,h,sizeof(h),BK4_BASE)!=(ssize_t)sizeof(h))return -2;
    if(memcmp(h+12,"BK4\0",4)||le32(h+0x10)!=819||
       le32(h+0x14)!=33018||le32(h+0x18)!=0x31A20||
       le32(h+0x1c)!=0x128ED8)return -3;
    uint32_t stored=le32(h+0x20);
    if(expected_checksum && stored!=expected_checksum)return -3;
    static const unsigned char table[6]={0x08,0x00,0x4a,0xea,0x0c,0xff};
    unsigned char actual_table[6]={0};
    if(pread(fd,actual_table,6,TABLE_OFFSET)!=6||
       memcmp(actual_table,table,6))return -4;
    if(pread(fd,chunk,SIZE,COLOR_OFFSET)!=SIZE||memcmp(chunk,value,SIZE))return -5;
    uint32_t calculated=0;
    if(record_sum(fd,&calculated)||calculated!=stored)return -6;
    if(observed_checksum)*observed_checksum=stored;
    return 0;
}
static int put_value(int fd,const unsigned char *value,uint32_t checksum){
    unsigned char le[4]={checksum,checksum>>8,checksum>>16,checksum>>24};
    if(pwrite(fd,value,SIZE,COLOR_OFFSET)!=SIZE)return -1;
    if(pwrite(fd,le,4,CHECKSUM_OFFSET)!=4)return -2;
    if(fsync(fd))return -3;
    return 0;
}

__attribute__((constructor))
static void run(void){
    if(!exact_child())return;
    struct result r={0};
    memcpy(r.magic,magic_text,sizeof(magic_text));
    r.version=1;r.pid=(uint32_t)getpid();r.stage=1;
    for(int i=0;i<2;++i){r.validate[i]=r.write_result[i]=INT32_MIN;
                            r.verify[i]=r.emergency[i]=INT32_MIN;}
    char text[sizeof(preload_text)]={0};
    int fd=open(preload_path,O_RDONLY|O_CLOEXEC|O_NOFOLLOW);
    if(fd<0){r.error=1;goto done;}
    ssize_t n=read(fd,text,sizeof(text));close(fd);
    if(n!=(ssize_t)sizeof(preload_text)-1||
       memcmp(text,preload_text,sizeof(preload_text)-1)){r.error=2;goto done;}
    r.checks|=1;
    if(unlink(preload_path)){r.error=3;goto done;}
    r.checks|=2;
    struct statfs fs={0};
    if(statfs("/tmp_wbshd",&fs)||fs.f_type!=TMPFS_MAGIC){r.error=4;goto done;}
    r.checks|=4;
    fd=open("/setting/updater/dat4",O_RDONLY|O_CLOEXEC|O_NOFOLLOW);
    if(fd<0){r.error=5;goto done;}
    uint16_t dat4=0;n=read(fd,&dat4,2);close(fd);r.dat4=dat4;
    if(n!=2||dat4!=0x0200){r.error=6;goto done;}
    r.stage=2;r.checks|=8;
    alarm(30);
    int handles[2]={-1,-1};
    for(int i=0;i<2;++i){
        handles[i]=open(files[i],O_RDWR|O_CLOEXEC|O_NOFOLLOW);
        if(handles[i]<0){r.error=7;goto close_files;}
        r.validate[i]=validate_file(handles[i],original_property,0,
                                     &r.old_checksum[i]);
        if(r.validate[i]){r.error=8;goto close_files;}
        r.new_checksum[i]=r.old_checksum[i]+CHECKSUM_DELTA;
    }
    r.stage=3;r.checks|=16;
    for(int i=0;i<2;++i){
        r.write_result[i]=put_value(handles[i],fl23_property,r.new_checksum[i]);
        if(r.write_result[i]){r.error=9;goto recover;}
    }
    r.stage=4;r.checks|=32;
    for(int i=0;i<2;++i){
        r.verify[i]=validate_file(handles[i],fl23_property,r.new_checksum[i],0);
        if(r.verify[i]){r.error=10;goto recover;}
    }
    r.stage=5;r.checks|=64;
    goto close_files;
recover:
    for(int i=0;i<2;++i){
        if(handles[i]>=0){
            int e=put_value(handles[i],original_property,r.old_checksum[i]);
            r.emergency[i]=e?e:validate_file(handles[i],original_property,
                                             r.old_checksum[i],0);
        }
    }
close_files:
    for(int i=0;i<2;++i)if(handles[i]>=0)close(handles[i]);
    alarm(0);
    if(!r.error){r.stage=6;r.checks|=128;}
done:
    emit(&r);
    _exit(0);
}
