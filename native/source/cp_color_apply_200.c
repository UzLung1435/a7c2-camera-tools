/* Bounded AP-DMA update of the CP's live 8 KiB color block on body 2.05.
 * This changes RAM only; both BK4 backup files remain untouched. A power
 * cycle reloads the original property unless a separate persistence step runs.
 */
#define _GNU_SOURCE
#include <stdint.h>
#include <stddef.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <dlfcn.h>
#include <limits.h>
#include <sys/mman.h>
#include <sys/statfs.h>

#include "color_property_slots.h"

#ifndef RESTORE
#error RESTORE must be 0 (apply) or 1 (restore)
#endif
enum { TMPFS_MAGIC=0x01021994, BLOCK_SIZE=8192, DMM_SIZE=4096 };
static const uint64_t CP_COLOR_VA=0x01793BB0ULL;
struct __attribute__((packed)) result {
    char magic[16];
    uint32_t version,stage,checks,pid,error,dat4,handle,mode;
    uint64_t phys;
    int32_t read_before[2],cache_before[2],write_result[2],cache_after[2];
    int32_t read_after[2],emergency_restore;
    uint32_t before_kind,after_kind,crc_before,crc_after,crc;
};
_Static_assert(sizeof(struct result)==120,"CP color RAM marker ABI");
static const char expected_cmdline[]="/bin/sh\0-c\0/bin/date -s 070421422017.26";
static const char preload_path[]="/etc/ld.so.preload";
#if RESTORE
static const char preload_text[]="/tmp_wbshd/libcodex_cp_fl23_color_ram_restore205.so\n";
static const char marker_path[]="/tmp_wbshd/codex_cp_fl23_color_ram_restore205.bin";
static const char magic_text[]="A7C2CPCLR205R";
#else
static const char preload_text[]="/tmp_wbshd/libcodex_cp_fl23_color_ram_apply205.so\n";
static const char marker_path[]="/tmp_wbshd/codex_cp_fl23_color_ram_apply205.bin";
static const char magic_text[]="A7C2CPCLR205A";
#endif
static const uint8_t alloc_sig[16]={0xfd,0x7b,0xb8,0xa9,0xfd,0x03,0x00,0x91,
                                    0xa2,0xf3,0x00,0x91,0xf3,0x53,0x01,0xa9};
static const uint8_t free_sig[16]={0xfd,0x7b,0xbc,0xa9,0xa1,0x07,0x80,0x52,
                                   0xfd,0x03,0x00,0x91,0xa2,0xb3,0x00,0x91};
static const uint8_t dma_sig[16]={0xfd,0x7b,0xb6,0xa9,0x1f,0x00,0x00,0x71,
                                  0xfd,0x03,0x00,0x91,0xf9,0x23,0x00,0xf9};
static const uint8_t cache_sig[16]={0xfd,0x7b,0xbc,0xa9,0x23,0x00,0x80,0x52,
                                    0xfd,0x03,0x00,0x91,0xf5,0x5b,0x02,0xa9};
static uint8_t before[BLOCK_SIZE],after[BLOCK_SIZE];

typedef uint64_t (*alloc_fn)(uint32_t,uint32_t *);
typedef void (*free_fn)(uint32_t);
typedef int32_t (*dma_fn)(int32_t,uint64_t,uint64_t,uint32_t);
typedef int32_t (*cache_fn)(int32_t,uint64_t,uint32_t);

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
static int read_block(dma_fn transfer,uint64_t phys,
                      const volatile uint8_t *mapped,uint8_t *dest,int32_t status[2]){
    for(int part=0;part<2;++part){
        status[part]=transfer(0,CP_COLOR_VA+(uint64_t)part*DMM_SIZE,phys,DMM_SIZE);
        if(status[part])return -1;
        for(size_t i=0;i<DMM_SIZE;++i)dest[part*DMM_SIZE+i]=mapped[i];
    }
    return 0;
}
static int write_block(dma_fn transfer,cache_fn cache,uint64_t phys,
                       volatile uint8_t *mapped,const uint8_t *src,
                       int32_t before_cache[2],int32_t writes[2],
                       int32_t after_cache[2]){
    for(int part=0;part<2;++part){
        uint64_t at=CP_COLOR_VA+(uint64_t)part*DMM_SIZE;
        before_cache[part]=cache(1,at,DMM_SIZE);
        if(before_cache[part])return -1;
        for(size_t i=0;i<DMM_SIZE;++i)mapped[i]=src[part*DMM_SIZE+i];
        writes[part]=transfer(1,phys,at,DMM_SIZE);
        if(writes[part])return -2;
        /* Match the previously healthy CP RAM-write path: cache RPC before
         * DMA, then exact CP->AP readback. A second clean after DMA could
         * overwrite the newly transferred bytes from stale CP cache. */
        after_cache[part]=0;
    }
    return 0;
}

__attribute__((constructor))
static void run(void){
    if(!exact_child())return;
    struct result r={0};
    memcpy(r.magic,magic_text,sizeof(magic_text));
    r.version=1;r.pid=(uint32_t)getpid();r.mode=RESTORE;r.stage=1;
    for(int i=0;i<2;++i){
        r.read_before[i]=r.cache_before[i]=r.write_result[i]=INT32_MIN;
        r.cache_after[i]=r.read_after[i]=INT32_MIN;
    }
    r.emergency_restore=INT32_MIN;
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
    alarm(15);
    void *lib=dlopen("/usr/lib/libsencore.so",RTLD_LAZY|RTLD_GLOBAL);
    if(!lib){r.error=7;goto done_alarm;}
    alloc_fn allocate=(alloc_fn)dlsym(lib,"_Z9dmm_allocjPj");
    free_fn release=(free_fn)dlsym(lib,"_Z8dmm_freej");
    dma_fn transfer=(dma_fn)dlsym(lib,"sen_dma_transfer");
    cache_fn cache=(cache_fn)dlsym(lib,"_Z20sen_control_cache_cpimj");
    if(!allocate||!release||!transfer||!cache||
       memcmp((const void *)allocate,alloc_sig,16)||
       memcmp((const void *)release,free_sig,16)||
       memcmp((const void *)transfer,dma_sig,16)||
       memcmp((const void *)cache,cache_sig,16)){
        r.error=8;goto close_lib;}
    r.stage=3;r.checks|=16;
    uint32_t handle=0;
    uint64_t phys=allocate(DMM_SIZE,&handle);r.handle=handle;r.phys=phys;
    if(!phys||!handle||(phys&15)){r.error=9;goto free_buffer;}
    r.stage=4;r.checks|=32;
    fd=open("/dev/mem",O_RDWR|O_SYNC|O_CLOEXEC|O_NOFOLLOW);
    if(fd<0){r.error=10;goto free_buffer;}
    uint64_t page=phys&~4095ULL;
    size_t delta=(size_t)(phys-page);
    void *mapped=mmap(NULL,delta+DMM_SIZE,PROT_READ|PROT_WRITE,MAP_SHARED,fd,(off_t)page);
    if(mapped==MAP_FAILED){r.error=11;goto close_mem;}
    volatile uint8_t *buffer=(volatile uint8_t *)mapped+delta;
    r.stage=5;r.checks|=64;
    if(read_block(transfer,phys,buffer,before,r.read_before)){r.error=12;goto unmap_mem;}
    r.crc_before=crc32(before,BLOCK_SIZE);
    if(!memcmp(before,original_property,BLOCK_SIZE))r.before_kind=1;
    else if(!memcmp(before,fl23_property,BLOCK_SIZE))r.before_kind=2;
    else {r.error=13;goto unmap_mem;}
#if RESTORE
    if(r.before_kind!=2){r.error=14;goto unmap_mem;}
    const uint8_t *target=original_property;
#else
    if(r.before_kind!=1){r.error=14;goto unmap_mem;}
    const uint8_t *target=fl23_property;
#endif
    r.stage=6;r.checks|=128;
    if(write_block(transfer,cache,phys,buffer,target,
                   r.cache_before,r.write_result,r.cache_after)){
        r.error=15;goto emergency;
    }
    r.stage=7;r.checks|=256;
    if(read_block(transfer,phys,buffer,after,r.read_after)){
        r.error=16;goto emergency;
    }
    r.crc_after=crc32(after,BLOCK_SIZE);
    if(!memcmp(after,original_property,BLOCK_SIZE))r.after_kind=1;
    else if(!memcmp(after,fl23_property,BLOCK_SIZE))r.after_kind=2;
#if RESTORE
    if(r.after_kind!=1){r.error=17;goto emergency;}
#else
    if(r.after_kind!=2){r.error=17;goto emergency;}
#endif
    r.stage=8;r.checks|=512;
    goto unmap_mem;
emergency:
    {
        int32_t c0[2]={INT32_MIN,INT32_MIN},w0[2]={INT32_MIN,INT32_MIN};
        int32_t c1[2]={INT32_MIN,INT32_MIN};
        r.emergency_restore=write_block(transfer,cache,phys,buffer,before,c0,w0,c1);
    }
unmap_mem:
    if(munmap(mapped,delta+DMM_SIZE)){r.error=18;}
close_mem:
    if(close(fd)){r.error=19;}
free_buffer:
    if(handle)release(handle);
close_lib:
    dlclose(lib);
done_alarm:
    alarm(0);
    if(!r.error){r.stage=9;r.checks|=1024;}
done:
    emit(&r);
    _exit(0);
}
