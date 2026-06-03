#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <dirent.h>
#include <unistd.h>
#include <sys/sysinfo.h>
#include <sys/resource.h>
#include <sys/epoll.h>
#include <sys/inotify.h>
#include <fcntl.h>
#include <cerrno>
#include <csignal>
#include <chrono>
#include <thread>
#include <string>
#include <vector>
#include <map>
#include <set>
#include <algorithm>
#include <fstream>
#include <unordered_map>
#include <sys/syscall.h>
#include <bpf/libbpf.h>
static inline int bpf_map_lookup_elem(int fd,const void*k,void*v){union bpf_attr a={};a.map_fd=(__u32)fd;a.key=(__u64)(unsigned long)k;a.value=(__u64)(unsigned long)v;return syscall(__NR_bpf,1,&a,sizeof(a));}
#include "fermata_core.skel.h"
using namespace std;

enum{SUPER_CORE_START=6,FERMATA_CPU_START=0,FERMATA_CPU_END=5,BIG_CORE_CACHE_NS=30000000000LL,CLEANUP_MOD=20};

static volatile sig_atomic_t keep_running=1;
struct FreezeState{int pid=0,tombstone=0;uint64_t frozen_at=0,setprio_at=0;float last_cpu=0;
    bool is_frozen=false,cpu_ready=false,is_cached=false,has_note=false,big_cores=false;
    uint32_t cache_age=0,abuse_cnt=0,big_core_cnt=0,cached_cycle=0,note_cycle=0;
    uint64_t big_checked_ts=0;string cg_path;};
static map<int,FreezeState>g_fs;static map<int,string>g_name_cache;
static set<string>g_whitelist,g_user_wl;
static long g_ticks=100;static int g_ncores=8,g_cycle=0,g_debug=0;
static bool g_doze=false,g_hyperos=false;static int g_cached_adj=900,g_freeze_delay=1,g_scan_ms=3000,g_idle_ms=8000,g_mem_low=2000,g_mem_mid=4000,g_tombstone_max=1,g_frz_cd_s=5,g_pri_cd_s=8,g_cache_refresh=60,g_cpu_abuse_pct=5,g_cpu_abuse_cnt=3;
static int g_epfd=-1,g_inotify_fd=-1,g_inotify_wd=-1;
static fermata_core_bpf *g_skel=nullptr;static ring_buffer *g_rb=nullptr;
static map<int,uint64_t>g_last_cpu;static map<int,uint64_t>g_last_ts;

static const char*kWl[]={"com.android.","systemui","audioserver","cameraserver","servicemanager",
    "system_server","surfaceflinger","logd","lmkd","netd","zygote64","zygote","init",
    "kgsl","adsp","cdsp","msm_","qseecom","irq/","kworker","kthreadd","rcu",
    "ksoftirqd","migration","watchdog","thermal","pm_","gpu_","vendor.","sched",nullptr};

static void on_signal(int){keep_running=0;}
static void setup_signals(){signal(SIGPIPE,SIG_IGN);struct sigaction sa{};sa.sa_handler=on_signal;sigaction(SIGTERM,&sa,nullptr);sigaction(SIGINT,&sa,nullptr);}
static void bind_cores(){cpu_set_t cs;CPU_ZERO(&cs);for(int i=FERMATA_CPU_START;i<=FERMATA_CPU_END;i++)CPU_SET(i,&cs);sched_setaffinity(0,sizeof(cs),&cs);}
static void set_ioprio_idle(){char cmd[64];snprintf(cmd,sizeof(cmd),"ionice -p %d -c 3",getpid());system(cmd);}
static int get_free_mem_mb(){struct sysinfo_full{long u;unsigned long l[3],t,fre,sh,buf,tsw,fr;unsigned short p,pa;unsigned long th,fh;unsigned m;char _[0];}si;if(sysinfo((struct sysinfo*)&si))return 9999;auto mb=(si.fre+si.buf)*si.m/1024/1024;return mb>9999?9999:(int)mb;}

static void load_config(){
    ifstream f("/data/adb/modules/fermata/fermata.conf");if(!f.is_open())return;
    string line;while(getline(f,line)){while(!line.empty()&&(line.back()=='\r'||line.back()==' '))line.pop_back();
        if(line.empty()||line[0]=='#')continue;size_t eq=line.find('=');if(eq==string::npos)continue;
        string key=line.substr(0,eq),val=line.substr(eq+1);while(!key.empty()&&key.back()==' ')key.pop_back();
        if(key=="whitelist"){g_user_wl.clear();size_t p=0;while(p<val.size()){size_t c=val.find(',',p);if(c==string::npos)c=val.size();
            string it=val.substr(p,c-p);while(!it.empty()&&it.front()==' ')it.erase(0,1);while(!it.empty()&&it.back()==' ')it.pop_back();
            if(!it.empty())g_user_wl.insert(it);p=c+1;}}
        else if(key=="freeze_delay"){int v=atoi(val.c_str());if(v>=0)g_freeze_delay=v;}
        else if(key=="scan_ms"){int v=atoi(val.c_str());if(v>=500)g_scan_ms=v;}
        else if(key=="idle_ms"){int v=atoi(val.c_str());if(v>=1000)g_idle_ms=v;}
        else if(key=="mem_low"){int v=atoi(val.c_str());if(v>=100)g_mem_low=v;}
        else if(key=="mem_mid"){int v=atoi(val.c_str());if(v>=200)g_mem_mid=v;}
        else if(key=="tombstone_max"){int v=atoi(val.c_str());if(v>=0)g_tombstone_max=v;}
        else if(key=="frz_cooldown"){int v=atoi(val.c_str());if(v>=1)g_frz_cd_s=v;}
        else if(key=="pri_cooldown"){int v=atoi(val.c_str());if(v>=1)g_pri_cd_s=v;}
        else if(key=="cache_refresh"){int v=atoi(val.c_str());if(v>=10)g_cache_refresh=v;}
        else if(key=="cpu_abuse_pct"){int v=atoi(val.c_str());if(v>=0)g_cpu_abuse_pct=v;}
        else if(key=="cpu_abuse_cnt"){int v=atoi(val.c_str());if(v>=1)g_cpu_abuse_cnt=v;}
        else if(key=="debug_log"){g_debug=atoi(val.c_str());}
    }}
static void get_process_name(int pid,string&out){auto it=g_name_cache.find(pid);if(it!=g_name_cache.end()){out=it->second;return;}
    char p[64];snprintf(p,sizeof(p),"/proc/%d/comm",pid);FILE*f=fopen(p,"r");if(!f){out.clear();return;}
    char b[256];if(fgets(b,sizeof(b),f)){out=b;while(!out.empty()&&out.back()=='\n')out.pop_back();g_name_cache[pid]=out;}fclose(f);}
static bool is_wl(const string&n){if(n.empty())return false;if(n.find(":push")!=string::npos)return true;
    for(const auto&w:g_whitelist)if(n.find(w)!=string::npos)return true;for(const auto&w:g_user_wl)if(n.find(w)!=string::npos)return true;return false;}
static bool uses_big_cores(int pid,FreezeState&fs){auto ns=chrono::steady_clock::now().time_since_epoch().count();
    if(fs.big_checked_ts>0&&(ns-fs.big_checked_ts)<BIG_CORE_CACHE_NS)return fs.big_cores;fs.big_checked_ts=ns;
    char p[64];DIR*d;snprintf(p,sizeof(p),"/proc/%d/task",pid);d=opendir(p);if(!d){fs.big_cores=false;return false;}
    dirent*e;bool found=false;while((e=readdir(d))){if(e->d_type!=DT_DIR||!atoi(e->d_name))continue;
        char s[128];snprintf(s,sizeof(s),"/proc/%d/task/%s/stat",pid,e->d_name);FILE*f=fopen(s,"r");if(!f)continue;
        int cpu=-1;fscanf(f,"%*d %*s %*c %*d %*d %*d %*d %*d %*u %*u %*u %*u %*u %*u %*u %*u %*u %*u %*u %*u %*u %*u %*u %*u %*u %*u %*u %*u %*u %*u %*u %*u %*u %*u %*u %*u %*u %*u %d",&cpu);fclose(f);
        if(cpu>=SUPER_CORE_START){found=true;break;}}closedir(d);fs.big_cores=found;return found;}
static bool is_cached_app(int pid,FreezeState&fs){if(fs.cache_age>0&&g_cycle-fs.cache_age<g_cache_refresh)return fs.is_cached;
    char p[64];snprintf(p,sizeof(p),"/proc/%d/oom_score_adj",pid);FILE*f=fopen(p,"r");if(!f)return false;
    int adj;bool c=(fscanf(f,"%d",&adj)==1&&adj>=g_cached_adj);fclose(f);fs.is_cached=c;fs.cache_age=g_cycle;return c;}
static float calc_cpu_ebpf(int pid){if(!g_skel)return 0;
    int fd=bpf_map__fd(g_skel->maps.cpu_time);if(fd<0)return 0;int nc=libbpf_num_possible_cpus();if(nc<=0)nc=8;
    vector<uint64_t>v(nc);uint32_t k=pid;if(bpf_map_lookup_elem(fd,&k,v.data())!=0)return 0;
    uint64_t total=0;for(int i=0;i<nc;i++)total+=v[i];auto now=chrono::steady_clock::now().time_since_epoch().count();
    auto it=g_last_ts.find(pid);if(it==g_last_ts.end()){g_last_cpu[pid]=total;g_last_ts[pid]=now;return-1;}
    uint64_t e=now-it->second;if(e<1000000000ULL)return-1;uint64_t d=total-g_last_cpu[pid];
    g_last_cpu[pid]=total;g_last_ts[pid]=now;return(float)((double)d/(double)e*100.0);}
static bool check_doze(){FILE*f=popen("dumpsys deviceidle get deep","r");if(!f)return false;
    char b[32]={};fgets(b,sizeof(b),f);pclose(f);return strstr(b,"true")||strstr(b,"enabled");}
static bool has_notification(int pid,FreezeState&fs){if(fs.note_cycle==g_cycle)return fs.has_note;
    char p[64];snprintf(p,sizeof(p),"/proc/%d/fd",pid);DIR*d=opendir(p);if(!d)return false;
    dirent*e;bool has=false;while((e=readdir(d))){if(e->d_type==DT_LNK&&strstr(e->d_name,"notif")){has=true;break;}}closedir(d);
    fs.has_note=has;fs.note_cycle=g_cycle;return has;}
static void force_stop(int pid){kill(pid,SIGKILL);}
static bool has_active_binder(int pid){char p[64];snprintf(p,sizeof(p),"/proc/%d/status",pid);FILE*f=fopen(p,"r");if(!f)return false;
    char l[256];while(fgets(l,sizeof(l),f)){if(strncmp(l,"Binder:",7)==0){int c=0;sscanf(l+7,"%d",&c);fclose(f);return c>0;}}fclose(f);return false;}
static bool get_cgroup_path(int pid,string&out){char p[64];snprintf(p,sizeof(p),"/proc/%d/cgroup",pid);FILE*f=fopen(p,"r");if(!f)return false;
    char l[512];while(fgets(l,sizeof(l),f)){if(strncmp(l,"0::",3)==0){char*e=l+3;while(*e&&*e!='\n')e++;*e=0;out="/sys/fs/cgroup";out+=l+3;fclose(f);return true;}}fclose(f);return false;}
static void check_frozen_event(int pid,FreezeState&fs){if(fs.cg_path.empty())return;
    int fd=open((fs.cg_path+"/cgroup.events").c_str(),O_RDONLY);if(fd<0)return;char b[256];ssize_t n=read(fd,b,255);close(fd);
    if(n>0){b[n]=0;if(strstr(b,"frozen 1"))fs.is_frozen=true;}}
static void freeze(int pid){auto&fs=g_fs[pid];if(fs.is_frozen)return;if(has_active_binder(pid))return;
    if(fs.cg_path.empty())get_cgroup_path(pid,fs.cg_path);if(!fs.cg_path.empty()){
        FILE*f=fopen((fs.cg_path+"/cgroup.freeze").c_str(),"w");if(f){fprintf(f,"1\n");fclose(f);setpriority(PRIO_PROCESS,pid,19);check_frozen_event(pid,fs);return;}}
    if(!fs.is_frozen&&kill(pid,SIGSTOP)==0){fs.is_frozen=true;setpriority(PRIO_PROCESS,pid,19);}}
static void unfreeze(int pid){auto&fs=g_fs[pid];if(!fs.is_frozen)return;setpriority(PRIO_PROCESS,pid,0);
    if(!fs.cg_path.empty()){FILE*f=fopen((fs.cg_path+"/cgroup.freeze").c_str(),"w");if(f)fprintf(f,"0\n");fclose(f);}fs.is_frozen=false;}
static void restore_all(){for(auto&[pid,fs]:g_fs){if(fs.is_frozen){setpriority(PRIO_PROCESS,pid,0);
    if(!fs.cg_path.empty()){FILE*f=fopen((fs.cg_path+"/cgroup.freeze").c_str(),"w");if(f)fprintf(f,"0\n");fclose(f);}else kill(pid,SIGCONT);}}}

static int handle_exit(void*,void*d,size_t sz){
    if(sz<4)return 0;uint32_t pid=*(uint32_t*)d;g_fs.erase(pid);g_name_cache.erase(pid);g_last_cpu.erase(pid);g_last_ts.erase(pid);return 0;}

static int schedule_processes(){
    g_cycle++;if(g_cycle%60==0)g_doze=check_doze();
    int fm=get_free_mem_mb(),big_wake=0;DIR*dir=opendir("/proc");if(!dir)return g_scan_ms;
    vector<pair<int,float>>sorted;dirent*e;int do_frz=0,do_kill=0,gone=0,frozen_count=0;
    while((e=readdir(dir))){if(e->d_type!=DT_DIR)continue;int pid=atoi(e->d_name);if(pid<=1||pid==getpid())continue;
        string name;get_process_name(pid,name);if(is_wl(name))continue;auto&fs=g_fs[pid];if(fs.pid==0)fs.pid=pid;
        bool cached=is_cached_app(pid,fs);
        if(!cached&&fs.is_frozen)fs.cache_age=0;
        if(!cached){fs.big_core_cnt=0;if(!fs.is_frozen)continue;}
        if(cached&&g_cycle%10==0&&uses_big_cores(pid,fs)){fs.big_core_cnt++;big_wake++;}
        else if(!cached)fs.big_core_cnt=0;
        if(cached&&!fs.is_frozen&&!fs.cpu_ready){if(fs.cached_cycle==0)fs.cached_cycle=g_cycle;
            if(g_cycle-fs.cached_cycle>=g_freeze_delay){auto now=chrono::steady_clock::now().time_since_epoch().count();
                if((fs.frozen_at==0||now-fs.frozen_at>=(g_frz_cd_s*1000000000LL))&&!has_notification(pid,fs)){freeze(pid);fs.frozen_at=now;fs.cached_cycle=0;do_frz++;continue;}}}
        else if(!cached)fs.cached_cycle=0;
        if(fs.is_frozen&&fs.cpu_ready){sorted.push_back({pid,fs.last_cpu});continue;}
        float cpu=calc_cpu_ebpf(pid);if(cpu<0){fs.last_cpu=0;continue;}fs.last_cpu=cpu;fs.cpu_ready=true;sorted.push_back({pid,cpu});}
    closedir(dir);
    if(!sorted.empty()){sort(sorted.begin(),sorted.end(),[](auto&a,auto&b){return a.second>b.second;});
        size_t half=sorted.size()/2;auto now=chrono::steady_clock::now().time_since_epoch().count();
        for(size_t i=0;i<sorted.size();++i){int pid=sorted[i].first;auto&fs=g_fs[pid];
            if(fs.is_frozen&&sorted[i].second>=g_cpu_abuse_pct){if(++fs.abuse_cnt>=g_cpu_abuse_cnt){if(is_cached_app(pid,fs))force_stop(pid);g_fs.erase(pid);g_name_cache.erase(pid);g_last_cpu.erase(pid);g_last_ts.erase(pid);do_kill++;continue;}}
            else fs.abuse_cnt=0;int tomb_limit=(fs.big_core_cnt>=3)?0:g_tombstone_max;bool note=has_notification(pid,fs);
            bool trigger=(fm<g_mem_low&&i>=half)||(fm<g_mem_mid&&i>=half)||(fs.tombstone>=tomb_limit&&is_cached_app(pid,fs));
            if(g_doze&&is_cached_app(pid,fs))trigger=true;if(note)trigger=false;
            if(trigger){if((fs.frozen_at==0||now-fs.frozen_at>=(g_frz_cd_s*1000000000LL))&&(fs.setprio_at==0||now-fs.setprio_at>=(g_pri_cd_s*1000000000LL))){
                if(!fs.is_frozen){freeze(pid);fs.frozen_at=now;fs.tombstone=0;do_frz++;fs.big_core_cnt=0;}}
            else if(!fs.is_frozen&&fs.tombstone>=tomb_limit){freeze(pid);fs.setprio_at=now;fs.tombstone=0;do_frz++;}}
            else{fs.tombstone=0;if(fs.is_frozen&&!is_cached_app(pid,fs))unfreeze(pid);}fs.last_cpu=sorted[i].second;}}
    for(auto&[pid,fs]:g_fs)if(fs.is_frozen)frozen_count++;
    static int lf=0,ok=0;bool st=(fm>=g_mem_mid&&frozen_count==lf);ok=st?ok+1:0;lf=frozen_count;
    if(g_debug&&g_cycle%5==0)printf("[Fermata] #%-5d mem=%-4dMB %s%s cached=%zu frz=%d kill=%d frozen=%d big=%d\n",g_cycle,fm,g_doze?"[Doze]":"",g_hyperos?"[MIUI]":"",sorted.size(),do_frz,do_kill,frozen_count,big_wake);
    return ok>5?g_idle_ms:g_scan_ms;}

static void detect_env(){FILE*fp=popen("getprop ro.build.version.sdk","r");if(fp){char b[128]={};fgets(b,sizeof(b),fp);pclose(fp);}
    fp=popen("getprop ro.miui.ui.version.name","r");if(fp){char b[128]={};if(fgets(b,sizeof(b),fp))g_hyperos=(strstr(b,"Hyper")||strstr(b,"V")||strstr(b,"OS"));pclose(fp);}
    if(g_hyperos)g_cached_adj=950;g_ticks=sysconf(_SC_CLK_TCK);g_ncores=get_nprocs();}
static void init_wl(){for(int i=0;kWl[i];++i)g_whitelist.insert(kWl[i]);}
static bool init_inotify(){g_inotify_fd=inotify_init1(IN_NONBLOCK);if(g_inotify_fd<0)return false;
    g_inotify_wd=inotify_add_watch(g_inotify_fd,"/data/adb/modules/fermata/fermata.conf",IN_CLOSE_WRITE|IN_MOVED_TO);
    if(g_inotify_wd<0){close(g_inotify_fd);return false;}epoll_event ev;ev.events=EPOLLIN;ev.data.fd=g_inotify_fd;
    if(epoll_ctl(g_epfd,EPOLL_CTL_ADD,g_inotify_fd,&ev)<0){close(g_inotify_fd);return false;}return true;}

int main(){
    setup_signals();bind_cores();set_ioprio_idle();init_wl();load_config();detect_env();
    g_epfd=epoll_create1(0);if(g_epfd<0){fprintf(stderr,"epoll failed\n");return 1;}
    init_inotify();
    g_skel=fermata_core_bpf::open_and_load();if(!g_skel){fprintf(stderr,"eBPF load failed\n");return 1;}
    fermata_core_bpf::attach(g_skel);g_rb=ring_buffer__new(bpf_map__fd(g_skel->maps.exit_events),handle_exit,nullptr,nullptr);
    if(g_rb){epoll_event ev;ev.events=EPOLLIN;ev.data.fd=ring_buffer__epoll_fd(g_rb);epoll_ctl(g_epfd,EPOLL_CTL_ADD,ev.data.fd,&ev);}
    char buf[64];time_t now=time(nullptr);strftime(buf,sizeof(buf),"[%Y-%m-%d %H:%M:%S] Fermata 启动",localtime(&now));
    puts(buf);fflush(stdout);this_thread::sleep_for(chrono::seconds(1));
    int next_ms=g_scan_ms;
    while(keep_running){epoll_event evs[8];int n=epoll_wait(g_epfd,evs,8,next_ms);if(n<0&&errno!=EINTR)break;
        for(int i=0;i<n;i++){int fd=evs[i].data.fd;if(fd==g_inotify_fd){char b[4096];read(g_inotify_fd,b,sizeof(b));g_user_wl.clear();load_config();}
        else if(g_rb&&fd==ring_buffer__epoll_fd(g_rb))ring_buffer__consume(g_rb);}
        next_ms=schedule_processes();}
    restore_all();if(g_rb)ring_buffer__free(g_rb);if(g_skel)fermata_core_bpf::destroy(g_skel);
    if(g_inotify_fd>=0){epoll_ctl(g_epfd,EPOLL_CTL_DEL,g_inotify_fd,nullptr);close(g_inotify_fd);}close(g_epfd);return 0;}
