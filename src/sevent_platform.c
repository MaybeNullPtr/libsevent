/* ==================== libsevent 平台抽象层实现 ============================= */

#include "sevent_platform.h"

/* ==================== 互斥锁 ==================== */

#ifdef SEVENT_RTOS

int sevent_mutex_init(sevent_mutex_t *m)
{
    /* TODO: RTOS 互斥量创建/初始化 */
    (void)m;
    return 0;
}

int sevent_mutex_lock(sevent_mutex_t *m)
{
    /* TODO: RTOS 加锁 */
    (void)m;
    return 0;
}

int sevent_mutex_unlock(sevent_mutex_t *m)
{
    /* TODO: RTOS 解锁 */
    (void)m;
    return 0;
}

int sevent_mutex_destroy(sevent_mutex_t *m)
{
    /* TODO: RTOS 销毁互斥量 */
    (void)m;
    return 0;
}

#else /* POSIX */

int sevent_mutex_init(sevent_mutex_t *m)
{
    return pthread_mutex_init(m, NULL);
}

int sevent_mutex_lock(sevent_mutex_t *m)
{
    return pthread_mutex_lock(m);
}

int sevent_mutex_unlock(sevent_mutex_t *m)
{
    return pthread_mutex_unlock(m);
}

int sevent_mutex_destroy(sevent_mutex_t *m)
{
    return pthread_mutex_destroy(m);
}

#endif /* SEVENT_RTOS */

/* ==================== Wakeup ==================== */

int sevent_wakeup_pair(int fds[2])
{
    fds[0] = fds[1] = -1;

    /* ---- Level 1: eventfd (Linux 2.6.22+, 最轻量) ---- */
#ifdef SEVENT_ENABLE_EVENTFD
    {
        int efd = eventfd(0, EFD_NONBLOCK);
        if (efd >= 0) { fds[0] = fds[1] = efd; return 0; }
        /* ENOSYS (kernel < 2.6.22) → fall through */
    }
#endif

    /* ---- Level 2: pipe (POSIX 轻量备选) ---- */
#ifdef SEVENT_ENABLE_PIPE
    if (pipe(fds) == 0)
    {
        int ok = 1;
        for (int i = 0; i < 2; i++)
        {
            int fl = fcntl(fds[i], F_GETFL);
            if (fl < 0) { ok = 0; break; }
            if (fcntl(fds[i], F_SETFL, fl | O_NONBLOCK) < 0) { ok = 0; break; }
        }
        if (ok) return 0;
        close(fds[0]); close(fds[1]);
        fds[0] = fds[1] = -1;
    }
#endif

    /* ---- Level 3: UDP loopback (通用降级) ---- */
    {
        int rd = -1, wr = -1;
        struct sockaddr_in addr;
        socklen_t addrlen = sizeof(addr);

        rd = socket(AF_INET, SOCK_DGRAM, 0);
        if (rd < 0) goto fail3;

        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        addr.sin_port = 0;
        if (bind(rd, (struct sockaddr*)&addr, sizeof(addr)) < 0) goto fail3;
        if (getsockname(rd, (struct sockaddr*)&addr, &addrlen) < 0) goto fail3;

        wr = socket(AF_INET, SOCK_DGRAM, 0);
        if (wr < 0) goto fail3;
        if (connect(wr, (struct sockaddr*)&addr, sizeof(addr)) < 0) goto fail3;

        for (int i = 0; i < 2; i++)
        {
            int fd = (i == 0) ? rd : wr;
            int fl = fcntl(fd, F_GETFL);
            if (fl < 0) goto fail3;
            if (fcntl(fd, F_SETFL, fl | O_NONBLOCK) < 0) goto fail3;
        }

        fds[0] = rd;
        fds[1] = wr;
        return 0;

    fail3:
        close(rd);
        if (wr >= 0) close(wr);
        fds[0] = fds[1] = -1;
        return -1;
    }
}

/* 排空 wakeup fd 读端的所有待处理字节 */
void sevent_wakeup_drain(int fd)
{
    char buf[64];
    while (read(fd, buf, sizeof(buf)) > 0) {}
}
