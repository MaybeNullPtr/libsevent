/* =========================================================================
 *  sevent_i.h — libsevent 内部工具头文件
 *
 *  不对外暴露. 内部各个编译单元通过此头访问内部分配器等基础能力.
 *  ========================================================================= */

#ifndef SEVENT_I_H
#define SEVENT_I_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ==================== 内部分配器 ====================
 *
 * 遵循 sevent_set_allocator 设置的分配器, 默认 = malloc/free.
 * 所有 libsevent 内部模块 (包括 WebSocket) 都应使用这些函数,
 * 而非直接调用 libc 的 malloc/free.
 */

void *sevent_i_malloc(size_t size);
void  sevent_i_free(void *ptr);
void *sevent_i_calloc(size_t nmemb, size_t size);

#ifdef __cplusplus
}
#endif

/* ==================== 分配器便利宏 ====================
 *
 * 自动推导类型, 消除显式 cast 和 sizeof.
 *
 *   struct foo *f;
 *   f = SEVENT_I_NEW(f);          // malloc(sizeof(*f)), 自动转型
 *   f = SEVENT_I_NEW0(f);         // calloc(1, sizeof(*f))
 *   f = SEVENT_I_NEW_ARR(f, n);   // malloc(n * sizeof(*f))
 */

#define SEVENT_I_NEW(ptr) ((__typeof__(ptr))sevent_i_malloc(sizeof(*(ptr))))
#define SEVENT_I_NEW0(ptr) ((__typeof__(ptr))sevent_i_calloc(1, sizeof(*(ptr))))
#define SEVENT_I_NEW_ARR(ptr, n) ((__typeof__(ptr))sevent_i_malloc((n) * sizeof(*(ptr))))

#endif /* SEVENT_I_H */
