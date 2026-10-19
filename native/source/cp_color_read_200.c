/* Read-only 0x2000-byte CP color configuration block snapshot, 2.04 body. */
#define _GNU_SOURCE
#include <stdint.h>
#include <stddef.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <dlfcn.h>
#include <limits.h>
#include <sys/mman.h>
#include <sys/statfs.h>

enum { TMPFS_MAGIC=0x01021994, BUFFER_BYTES=4096 };
struct __attribute__((packed)) result {
    char magic[16];
    uint32_t version,stage,checks,pid,error,dat4,handle;
    uint64_t phys;
    int32_t transfer_mode,transfer_first,transfer_second;
    uint8_t mode[16],block[8192];
    uint32_t crc;
};
_Static_assert(sizeof(struct result)==8276,"CP color block marker ABI");
static const char expected_cmdline[]="/bin/sh\0-c\0/bin/date -s 070421422017.26";
static const char preload_path[]="/etc/ld.so.preload";
static const char preload_text[]="/tmp_wbshd/libcodex_cp_color_block_ro205a.so\n";
static const char marker_path[]="/tmp_wbshd/codex_cp_color_block_ro205a.bin";
static const char magic_text[]="A7C2CPBLK205A";
static const uint8_t alloc_sig[16]={
    0xfd,0x7b,0xb8,0xa9,0xfd,0x03,0x00,0x91,
    0xa2,0xf3,0x00,0x91,0xf3,0x53,0x01,0xa9};
static const uint8_t free_sig[16]={
    0xfd,0x7b,0xbc,0xa9,0xa1,0x07,0x80,0x52,
    0xfd,0x03,0x00,0x91,0xa2,0xb3,0x00,0x91};
static const uint8_t dma_sig[16]={
    0xfd,0x7b,0xb6,0xa9,0x1f,0x00,0x00,0x71,
    0xfd,0x03,0x00,0x91,0xf9,0x23,0x00,0xf9};

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
__attribute__((constructor))
static void read_cp_color_block(void){
    if(!exact_child())return;
    struct result r={0};
    memcpy(r.magic,magic_text,14);
    r.version=1;r.pid=(uint32_t)getpid();r.stage=1;
    r.transfer_mode=r.transfer_first=r.transfer_second=INT32_MIN;
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
    uint16_t dat4=0;n=read(fd,&dat4,2);close(fd);
    r.dat4=dat4;
    if(n!=2||dat4!=0x0200){r.error=6;goto done;}
    r.stage=2;r.checks|=8;
    alarm(10);
    void *lib=dlopen("/usr/lib/libsencore.so",RTLD_LAZY|RTLD_GLOBAL);
    if(!lib){r.error=7;goto done_alarm;}
    typedef uint64_t (*alloc_fn)(uint32_t,uint32_t *);
    typedef void (*free_fn)(uint32_t);
    typedef int32_t (*dma_fn)(int32_t,uint64_t,uint64_t,uint32_t);
    alloc_fn allocate=(alloc_fn)dlsym(lib,"_Z9dmm_allocjPj");
    free_fn release=(free_fn)dlsym(lib,"_Z8dmm_freej");
    dma_fn transfer=(dma_fn)dlsym(lib,"sen_dma_transfer");
    if(!allocate||!release||!transfer||
       memcmp((const void *)allocate,alloc_sig,16)||
       memcmp((const void *)release,free_sig,16)||
       memcmp((const void *)transfer,dma_sig,16)){
        r.error=8;goto close_lib;}
    r.stage=3;r.checks|=16;
    uint32_t handle=0;
    uint64_t phys=allocate(BUFFER_BYTES,&handle);
    r.handle=handle;r.phys=phys;
    if(!phys||!handle||(phys&15)){r.error=9;goto free_buffer;}
    r.stage=4;r.checks|=32;
    fd=open("/dev/mem",O_RDONLY|O_SYNC|O_CLOEXEC|O_NOFOLLOW);
    if(fd<0){r.error=10;goto free_buffer;}
    uint64_t page=phys&~4095ULL;
    size_t delta=(size_t)(phys-page);
    if(delta+4096>BUFFER_BYTES+4095){r.error=11;goto close_mem;}
    void *mapped=mmap(NULL,delta+4096,PROT_READ,MAP_SHARED,fd,(off_t)page);
    if(mapped==MAP_FAILED){r.error=12;goto close_mem;}
    const volatile uint8_t *readback=(const volatile uint8_t *)mapped+delta;
    r.stage=5;r.checks|=64;
    r.transfer_mode=transfer(0,0x0165b080ULL,phys,16);
    if(r.transfer_mode){r.error=13;goto unmap_mem;}
    for(unsigned i=0;i<16;++i)r.mode[i]=readback[i];
    r.stage=6;r.checks|=128;
    r.transfer_first=transfer(0,0x01793bb0ULL,phys,4096);
    if(r.transfer_first){r.error=15;goto unmap_mem;}
    for(unsigned i=0;i<4096;++i)r.block[i]=readback[i];
    r.stage=7;r.checks|=256;
    r.transfer_second=transfer(0,0x01794bb0ULL,phys,4096);
    if(r.transfer_second){r.error=16;goto unmap_mem;}
    for(unsigned i=0;i<4096;++i)r.block[4096+i]=readback[i];
    r.stage=8;r.checks|=512;
unmap_mem:
    if(munmap(mapped,delta+4096)){r.error=17;}
close_mem:
    if(close(fd)){r.error=18;}
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
