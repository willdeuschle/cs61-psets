#include "io61.h"
#include <sys/types.h>
#include <sys/stat.h>
#include <limits.h>
#include <errno.h>
// mmap stuff
#include <sys/mman.h>

// io61.c
//    YOUR CODE HERE!
#define READ_ONLY '0'
#define WRITE_ONLY '1'
#define MAPPED '1'
#define NOT_MAPPED '0'

// io61_file
//    Data structure for io61 file wrappers. Add your own stuff.

struct io61_file {
    int fd;
    char mode; // READ: '0', WRITE: '1'
    unsigned char buf[BUFSIZ]; // buffer for our file
    // file position of first character in the cache
    off_t first_char;
    // READ: file position of next character to be read into the buffer
    // WRITE: file position of next character to be written out of buffer
    off_t current_char;
    // file position one character past end of buffer
    off_t end_char;

    // mmap stuff
    char mapped;
    off_t size;
    char* map;
};


// io61_fdopen(fd, mode)
//    Return a new io61_file for file descriptor `fd`. `mode` is
//    either O_RDONLY for a read-only file or O_WRONLY for a
//    write-only file. You need not support read/write files.

io61_file* io61_fdopen(int fd, int mode) {
    assert(fd >= 0);
    io61_file* f = (io61_file*) malloc(sizeof(io61_file));
    f->fd = fd;
    f->first_char = 0;
    f->current_char = 0;
    f->end_char = 0;
    f->mode = mode == O_RDONLY ? READ_ONLY : WRITE_ONLY;

    // get file size
    f->size = io61_filesize(f);

    if (mode == O_RDONLY) {
        // mmap stuff
        void* map = mmap(NULL, f->size, PROT_READ, MAP_PRIVATE, fd, 0);
        if (map == MAP_FAILED) {
            // for example, streams
            f->mapped = NOT_MAPPED;
        } else {
            f->mapped = MAPPED;
            f->map = (char*) map;
        }
    } else {
        // not mapping write files
        f->mapped = NOT_MAPPED;
    }

    return f;
}


// io61_close(f)
//    Close the io61_file `f` and release all its resources.

int io61_close(io61_file* f) {
    io61_flush(f);
    int r = close(f->fd);
    free(f);
    return r;
}


// io61_readc(f)
//    Read a single (unsigned) character from `f` and return it. Returns EOF
//    (which is -1) on error or end-of-file.

int io61_readc(io61_file* f) {
    unsigned char buf[1];
    // hand off call to io61_read
    /*if (read(f->fd, buf, 1) == 1) {*/
    if (io61_read(f, (char*) buf, 1) == 1) {
        return buf[0];
    } else {
        return EOF;
    }
}


// io61_read(f, buf, sz)
//    Read up to `sz` characters from `f` into `buf`. Returns the number of
//    characters read on success; normally this is `sz`. Returns a short
//    count, which might be zero, if the file ended before `sz` characters
//    could be read. Returns -1 if an error occurred before any characters
//    were read.

ssize_t io61_read(io61_file* f, char* buf, size_t sz) {
    size_t nread = 0;

    // mmap stuff
    if (f->mapped == MAPPED) {
        // mapped
        ssize_t to_read = sz;
        // stay inside file bounds
        if (f->current_char + to_read > f->size) {
            to_read = f->size - f->current_char;
        }
        // copy that much to our buffer
        memcpy(&buf[0], &f->map[f->current_char], to_read);
        // advance our pointer
        f->current_char += to_read;
        nread = to_read;
    } else {
        // not mapped
        // read until we hit the desired number
        while (nread != sz) {
            if (f->current_char < f->end_char) {
                // still have cache space
                // amount we want to read
                ssize_t to_read = sz - nread;
                // read as much from cache as possible
                if (f->end_char - f->current_char < to_read) {
                    to_read = f->end_char - f->current_char;
                }
                // copy that much to our buffer
                memcpy(&buf[nread], &f->buf[f->current_char - f->first_char], to_read);
                // increment our position in the cache and the number of characters read
                f->current_char += to_read;
                nread += to_read;
            } else {
                // invalid cache, read more data in
                // move first_char to where end_char is now
                f->first_char = f->end_char;
                // load data into buffer
                ssize_t num_read = read(f->fd, f->buf, BUFSIZ);
                if (num_read > 0) {
                    // more than 0 characters read, update end_char
                    f->end_char += num_read;
                } else {
                    // either failed or read 0 characters
                    // in either event, return nread if we have any, otherwise
                    // return 0 or -1 from the read call
                    return nread ? nread : num_read;
                }
            }
        }
    }

    return nread;
}


// io61_writec(f)
//    Write a single character `ch` to `f`. Returns 0 on success or
//    -1 on error.

int io61_writec(io61_file* f, int ch) {
    unsigned char buf[1];
    buf[0] = ch;
    // switch to io61_write
    /*if (write(f->fd, buf, 1) == 1) {*/
    if (io61_write(f, (char*) buf, 1) == 1) {
        return 0;
    } else {
        return -1;
    }
}


// io61_write(f, buf, sz)
//    Write `sz` characters from `buf` to `f`. Returns the number of
//    characters written on success; normally this is `sz`. Returns -1 if
//    an error occurred before any characters were written.

ssize_t io61_write(io61_file* f, const char* buf, size_t sz) {
    size_t nwritten = 0;
    while (nwritten != sz) {
        if (f->end_char - f->first_char < BUFSIZ) {
            // we still have more room in our buffer to absorb writes
            ssize_t to_write = sz - nwritten;
            // fill as much as the buffer will allow
            if (to_write > BUFSIZ - (f->end_char - f->first_char)) {
                to_write = BUFSIZ - (f->end_char - f->first_char);
            }
            // add to buffer
            memcpy(&f->buf[f->end_char - f->first_char], &buf[nwritten], to_write);
            // move our current_char and nwritten along
            f->end_char += to_write;
            nwritten += to_write;
        } else {
            // we've filled our buffer
            // write to disk
            ssize_t num_written = write(f->fd, &f->buf[f->current_char - f->first_char], f->end_char - f->current_char);
            if (num_written > 0) {
                // successfully wrote some data to disk, increment first_char
                f->current_char += num_written;
            } else {
                // either an error or no space to write
                // return nwritten if we have any, otherwise -1 or 0
                return nwritten ? nwritten : num_written;
            }

            // if we've fully written our buffer, empty the cache
            if (f->current_char == f->end_char) {
                f->first_char = f->end_char;
            }
        }
    }
    return nwritten;
}


// io61_flush(f)
//    Forces a write of all buffered data written to `f`.
//    If `f` was opened read-only, io61_flush(f) may either drop all
//    data buffered for reading, or do nothing.

int io61_flush(io61_file* f) {
    if (f->mode == WRITE_ONLY) {
        // write whatever is left in the buffer
        if (write(f->fd, &f->buf[f->current_char - f->first_char], f->end_char - f->current_char) == -1) {
            // failed to write
            return -1;
        }
        f->first_char = f->current_char = f->end_char;
    }
    return 0;
}


// io61_seek(f, pos)
//    Change the file pointer for file `f` to `pos` bytes into the file.
//    Returns 0 on success and -1 on failure.

int io61_seek(io61_file* f, off_t pos) {
    // mmap stuff
    if (f->mapped == MAPPED) {
        // mapped
        // seek to where they asked within the bounds of 0 and the size of the file
        size_t to_seek = pos;
        if (pos < 0) {
            to_seek = 0;
        } else if (pos > f->size) {
            to_seek = f->size;
        }
        f->current_char = to_seek;
        return 0;
    } else {
        if (f->mode == WRITE_ONLY) {
            // writing
            // flush first
            io61_flush(f);
            off_t seek_pos = lseek(f->fd, (off_t) pos, SEEK_SET);
            if (seek_pos != pos) {
                // failure
                return -1;
            }
            // reset first_char and end_char for our cache
            f->first_char = f->end_char = f->current_char = pos;
            return 0;
        } else {
            // reading
            if (pos < f->first_char || pos > f->end_char) {
                // this pos is not in our cache, so seek
                // align our seek for caching improvements
                off_t aligned_pos = pos - (pos % BUFSIZ);
                off_t seek_pos = lseek(f->fd, (off_t) aligned_pos, SEEK_SET);
                if (seek_pos != aligned_pos) {
                    // failure
                    return -1;
                }
                // reset first_char and end_char for our cache
                f->first_char = f->end_char = aligned_pos;
            }
            f->current_char = pos;
            return 0;
        }
    }
}


// You shouldn't need to change these functions.

// io61_open_check(filename, mode)
//    Open the file corresponding to `filename` and return its io61_file.
//    If `filename == NULL`, returns either the standard input or the
//    standard output, depending on `mode`. Exits with an error message if
//    `filename != NULL` and the named file cannot be opened.

io61_file* io61_open_check(const char* filename, int mode) {
    int fd;
    if (filename) {
        fd = open(filename, mode, 0666);
    } else if ((mode & O_ACCMODE) == O_RDONLY) {
        fd = STDIN_FILENO;
    } else {
        fd = STDOUT_FILENO;
    }
    if (fd < 0) {
        fprintf(stderr, "%s: %s\n", filename, strerror(errno));
        exit(1);
    }
    return io61_fdopen(fd, mode & O_ACCMODE);
}


// io61_filesize(f)
//    Return the size of `f` in bytes. Returns -1 if `f` does not have a
//    well-defined size (for instance, if it is a pipe).

off_t io61_filesize(io61_file* f) {
    struct stat s;
    int r = fstat(f->fd, &s);
    if (r >= 0 && S_ISREG(s.st_mode)) {
        return s.st_size;
    } else {
        return -1;
    }
}


// io61_eof(f)
//    Test if readable file `f` is at end-of-file. Should only be called
//    immediately after a `read` call that returned 0 or -1.

int io61_eof(io61_file* f) {
    char x;
    ssize_t nread = read(f->fd, &x, 1);
    if (nread == 1) {
        fprintf(stderr, "Error: io61_eof called improperly\n\
  (Only call immediately after a read() that returned 0 or -1.)\n");
        abort();
    }
    return nread == 0;
}
