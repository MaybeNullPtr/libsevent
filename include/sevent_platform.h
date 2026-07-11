/* ==================== libsevent 平台抽象层 ================================
 *
 * 抽象互斥锁、线程ID、wakeup 机制、信号等平台相关接口。
 *
 * POSIX:   pthread_mutex + pipe() + pthread_self/equal + sigaction
 * RTOS:    用户按实际 RTOS 填充骨架实现 + 回环 TCP wakeup
 * ========================================================================= */

#ifndef SEVENT_PLATFORM_H
#define SEVENT_PLATFORM_H

#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/select.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include <time.h>
#include <errno.h>
#include <signal.h>

#ifdef SEVENT_RTOS

/* ==================== RTOS 平台 ==================== */

/* ---- 互斥锁 ---- */
typedef struct {
    void *handle;               /* TODO: 替换为 RTOS 互斥量句柄 */
} sevent_mutex_t;

int sevent_mutex_init(sevent_mutex_t *m);
int sevent_mutex_lock(sevent_mutex_t *m);
int sevent_mutex_unlock(sevent_mutex_t *m);
int sevent_mutex_destroy(sevent_mutex_t *m);

/* ---- 线程ID ---- */
typedef unsigned long sevent_thread_t;
#define sevent_thread_self()       ((sevent_thread_t)0)      /* TODO */
#define sevent_thread_equal(a,b)   ((a) == (b))              /* TODO */

/* ---- 信号 ---- */
#define SEVENT_NO_SIGPIPE

#else /* ==================== POSIX 平台 ==================== */

#include <pthread.h>

#ifdef SEVENT_ENABLE_EVENTFD
#include <sys/eventfd.h>
#endif

/* ---- 互斥锁 ---- */
typedef pthread_mutex_t sevent_mutex_t;

int sevent_mutex_init(sevent_mutex_t *m);
int sevent_mutex_lock(sevent_mutex_t *m);
int sevent_mutex_unlock(sevent_mutex_t *m);
int sevent_mutex_destroy(sevent_mutex_t *m);

/* ---- 线程ID ---- */
typedef pthread_t sevent_thread_t;
#define sevent_thread_self()      pthread_self()
#define sevent_thread_equal(a,b)  pthread_equal(a,b)

#endif /* SEVENT_RTOS */

/* ==================== Wakeup ==================== */

/*
 * 创建一对用于唤醒的 fd (self-pipe 模式)。
 * fds[0] 为读端（加入 select rfds），fds[1] 为写端（用于 wakeup）。
 * 成功返回 0，失败返回 -1。
 */
int sevent_wakeup_pair(int fds[2]);

/*
 * 排空 wakeup fd 读端的所有待处理字节。
 */
void sevent_wakeup_drain(int fd);

#endif /* SEVENT_PLATFORM_H */
