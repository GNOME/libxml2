typedef void* xzFile;       /* opaque lzma file descriptor */

static xzFile xzopen(const char *path, const char *mode);
static xzFile xzdopen(int fd, const char *mode);
static int xzread(xzFile file, void *buf, unsigned len);
static int xzclose(xzFile file);
