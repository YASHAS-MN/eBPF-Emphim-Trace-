/* Test binary only: never link this file into the production replay. */
#include <errno.h>
#include <stddef.h>
#include <stdlib.h>

void *__real_calloc(size_t count, size_t size);
void *__wrap_calloc(size_t count, size_t size)
{
    static unsigned long calls;
    const char *configured = getenv("EPHIM_TEST_FAIL_CALLOC");
    unsigned long fail_at = configured ? strtoul(configured, NULL, 10) : 0;
    if (++calls == fail_at) {
        errno = ENOMEM;
        return NULL;
    }
    return __real_calloc(count, size);
}
