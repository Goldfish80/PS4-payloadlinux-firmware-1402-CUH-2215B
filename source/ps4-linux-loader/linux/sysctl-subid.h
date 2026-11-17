#ifndef LOCAL_SYSCTL_SUBID_H
#define LOCAL_SYSCTL_SUBID_H
/* FreeBSD sysctlnametomib uses __sysctl({0,3},...) to resolve a name;
 * then performs __sysctl on the resulting MIB. This avoids loading another
 * libkernel variant into a running system process. */
extern int __sysctl(const int *, unsigned int, void *, size_t *, const void *, size_t);
static int checked_sysctl_read(const char *name, size_t name_len, void *value, size_t *value_size)
{
    int resolve[2] = { 0, 3 }, oid[26];
    size_t oid_bytes = sizeof(oid);
    if (__sysctl(resolve, 2, oid, &oid_bytes, name, name_len) != 0 ||
        !oid_bytes || oid_bytes > sizeof(oid) || oid_bytes % sizeof(int)) return -1;
    return __sysctl(oid, (unsigned int)(oid_bytes / sizeof(int)), value,
                    value_size, NULL, 0);
}
static int checked_subid(void)
{
    const char name[] = "hw.sce_subsys_subid";
    unsigned int value = 0; size_t value_size = sizeof(value);
    if (checked_sysctl_read(name, sizeof(name)-1, &value, &value_size) != 0 ||
        value_size != sizeof(value)) return -1;
    return (int)value;
}
#endif
