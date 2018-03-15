#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netdb.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <stdio.h>
#include <errno.h>
#include <signal.h>
#include <assert.h>
#include <pthread.h>
#include <stdbool.h>
#include "serverinfo.h"

#define INIT_BACKOFF_MS 10000
#define MAX_BACKOFF_MS  128000000
#define CONNECTIONS_SLEEP_TIME 100000

static const char* pong_host = PONG_HOST;
static const char* pong_port = PONG_PORT;
static const char* pong_user = PONG_USER;
static struct addrinfo* pong_addr;

#define MAX_CONNECTIONS 30
// HELPER MIN FUNCTION 
static inline int min(int x, int y) {
    return x < y ? x : y;
}
// track whether last thread has received finishing information
bool last_thread_finished;
pthread_cond_t last_thread_finished_cond_var;
// lock last_thread_finished marker
pthread_mutex_t last_thread_finished_mutex;
// request mutex
pthread_mutex_t request_mutex;

// TIME HELPERS
double start_time = 0;

// tstamp()
//    Return the current absolute time as a real number of seconds.
double tstamp(void) {
    struct timespec now;
    clock_gettime(CLOCK_REALTIME, &now);
    return now.tv_sec + now.tv_nsec * 1e-9;
}

// elapsed()
//    Return the number of seconds that have elapsed since `start_time`.
double elapsed(void) {
    return tstamp() - start_time;
}


// HTTP CONNECTION MANAGEMENT

// `http_connection::cstate` values
typedef enum http_connection_state {
    cstate_idle = 0,        // Waiting to send request
    cstate_waiting = 1,     // Sent request, waiting to receive response
    cstate_headers = 2,     // Receiving headers
    cstate_body = 3,        // Receiving body
    cstate_closed = -1,     // Body complete, connection closed
    cstate_broken = -2      // Parse error
} http_connection_state;

// http_connection
//    This object represents an open HTTP connection to a server.
typedef struct http_connection http_connection;
struct http_connection {
    int fd;                 // Socket file descriptor

    http_connection_state cstate;  // Connection state (see above)
    int status_code;        // Response status code (e.g., 200, 402)
    size_t content_length;  // Content-Length value
    int has_content_length; // 1 iff Content-Length was provided
    int eof;                // 1 iff connection EOF has been reached

    char buf[BUFSIZ + 1];       // Response buffer
    size_t len;             // Length of response buffer
};

// helper functions
char* http_truncate_response(http_connection* conn);
static int http_process_response_headers(http_connection* conn);
static int http_check_response_body(http_connection* conn);

static void usage(void);


// http_connect(ai)
//    Open a new connection to the server described by `ai`. Returns a new
//    `http_connection` object for that server connection. Exits with an
//    error message if the connection fails.
http_connection* http_connect(const struct addrinfo* ai) {
    // connect to the server
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        perror("socket");
        exit(1);
    }

    int yes = 1;
    (void) setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int));

    int r = connect(fd, ai->ai_addr, ai->ai_addrlen);
    if (r < 0) {
        perror("connect");
        exit(1);
    }

    // construct an http_connection object for this connection
    http_connection* conn =
        (http_connection*) malloc(sizeof(http_connection));
    conn->fd = fd;
    conn->cstate = cstate_idle;
    conn->eof = 0;
    return conn;
}


// http_close(conn)
//    Close the HTTP connection `conn` and free its resources.
void http_close(http_connection* conn) {
    close(conn->fd);
    free(conn);
}


// http_send_request(conn, uri)
//    Send an HTTP POST request for `uri` to connection `conn`.
//    Exit on error.
void http_send_request(http_connection* conn, const char* uri) {
    assert(conn->cstate == cstate_idle);

    // prepare and write the request
    char reqbuf[BUFSIZ];
    size_t reqsz = snprintf(reqbuf, sizeof(reqbuf),
                            "POST /%s/%s HTTP/1.0\r\n"
                            "Host: %s\r\n"
                            "Connection: keep-alive\r\n"
                            "\r\n",
                            pong_user, uri, pong_host);
    assert(reqsz < sizeof(reqbuf));

    size_t pos = 0;
    while (pos < reqsz) {
        // acquire mutex here
        pthread_mutex_lock(&request_mutex);
        ssize_t nw = write(conn->fd, &reqbuf[pos], reqsz - pos);
        pthread_mutex_unlock(&request_mutex);
        if (nw == 0) {
            break;
        } else if (nw == -1 && errno != EINTR && errno != EAGAIN) {
            perror("write");
            exit(1);
        } else if (nw != -1) {
            pos += nw;
        }
    }

    if (pos != reqsz) {
        fprintf(stderr, "%.3f sec: connection closed prematurely\n",
                elapsed());
        exit(1);
    }

    // clear response information
    conn->cstate = cstate_waiting;
    conn->status_code = -1;
    conn->content_length = 0;
    conn->has_content_length = 0;
    conn->len = 0;
}


// http_receive_response_headers(conn)
//    Read the server's response headers and set `conn->status_code`
//    to the server's status code. If the connection terminates
//    prematurely, `conn->status_code` is -1.
void http_receive_response_headers(http_connection* conn) {
    assert(conn->cstate != cstate_idle);
    if (conn->cstate < 0) {
        return;
    }
    conn->buf[0] = 0;

    // read & parse data until `http_process_response_headers`
    // tells us to stop
    while (http_process_response_headers(conn)) {
        if (conn->len >= BUFSIZ) {
            // read more, they are trying to attack us with an unnecessarily
            // long header
            conn->len = 0;
        }
        ssize_t nr = read(conn->fd, &conn->buf[conn->len], BUFSIZ - conn->len);
        if (nr == 0) {
            conn->eof = 1;
        } else if (nr == -1 && errno != EINTR && errno != EAGAIN) {
            perror("read");
            exit(1);
        } else if (nr != -1) {
            conn->len += nr;
            conn->buf[conn->len] = 0;  // null-terminate
        }
    }

    // Status codes >= 500 mean we are overloading the server
    // and should exit.
    if (conn->status_code >= 500) {
        fprintf(stderr, "%.3f sec: exiting because of "
                "server status %d (%s)\n", elapsed(),
                conn->status_code, http_truncate_response(conn));
        exit(1);
    }
}


// http_receive_response_body(conn)
//    Read the server's response body. On return, `conn->buf` holds the
//    response body, which is `conn->len` bytes long and has been
//    null-terminated.
void http_receive_response_body(http_connection* conn) {
    assert(conn->cstate < 0 || conn->cstate == cstate_body);
    if (conn->cstate < 0) {
        return;
    }
    // NB: conn->buf might contain some body data already!

    // read response body (http_check_response_body tells us when to stop)
    while (http_check_response_body(conn)) {
        ssize_t nr = read(conn->fd, &conn->buf[conn->len], BUFSIZ);
        if (nr == 0) {
            conn->eof = 1;
        } else if (nr == -1 && errno != EINTR && errno != EAGAIN) {
            perror("read");
            exit(1);
        } else if (nr != -1) {
            conn->len += nr;
            conn->buf[conn->len] = 0;  // null-terminate
        }
    }
}


// http_truncate_response(conn)
//    Truncate the `conn` response text to a manageable length and return
//    that truncated text. Useful for error messages.
char* http_truncate_response(http_connection* conn) {
    char *eol = strchr(conn->buf, '\n');
    if (eol) {
        *eol = 0;
    }
    if (strnlen(conn->buf, 100) >= 100) {
        conn->buf[100] = 0;
    }
    return conn->buf;
}


// MAIN PROGRAM

typedef struct pong_args {
    int x;
    int y;
    http_connection* conn;
} pong_args; volatile int move_done;

// Connection linked list node
typedef struct Node {
    struct Node* next;
    struct Node* prev;
    struct http_connection* conn;
} Node;
struct Node* head;
pthread_mutex_t connection_list_mutex;

void push_connection(http_connection* conn) {
    assert(conn->cstate == cstate_idle);
    Node* new_node = malloc(sizeof(Node)); 
    new_node->conn = conn; 
    // reset the buffer space available for this connection
    conn->len = 0;

    pthread_mutex_lock(&connection_list_mutex); // acquire lock
    new_node->next = head;
    head = new_node; 
    pthread_mutex_unlock(&connection_list_mutex); // release lock
}

void init_connections(void) {
    pthread_mutex_init(&connection_list_mutex, NULL);

    pthread_mutex_lock(&connection_list_mutex);
    head = NULL;
    pthread_mutex_unlock(&connection_list_mutex);

    for (int i  = 0; i < MAX_CONNECTIONS; i++) {
         http_connection* new_conn = http_connect(pong_addr);
         push_connection(new_conn);
    }
}

http_connection* pop_connection(void) {
    http_connection* idle_conn = NULL; 
    pthread_mutex_lock(&connection_list_mutex); 
    if (head != NULL) {
        idle_conn = head->conn; 
        Node* tmp = head; 
        head = head->next; 
        free(tmp); 
    }
    pthread_mutex_unlock(&connection_list_mutex);
    if (idle_conn) {
        assert(idle_conn && idle_conn->cstate == cstate_idle);
    }
    return idle_conn; 
}

// pong_thread(threadarg)
//    Connect to the server at the position indicated by `threadarg`
//    (which is a pointer to a `pong_args` structure).
void* pong_thread(void* threadarg) {
    pthread_detach(pthread_self());

    // Copy thread arguments onto our stack.
    pong_args pa = *((pong_args*) threadarg);
    // access this connection
    http_connection* conn = pa.conn;
    assert(conn->cstate == cstate_idle);

    char url[256];
    snprintf(url, sizeof(url), "move?x=%d&y=%d&style=on",
             pa.x, pa.y);
    
    int move_success = 0; 
    int backoff_ms = 0; 

    // while loop to keep trying to send message 
    // until connection is not dropped 
    do {
        if (backoff_ms == 0) {
            // initialize backoff for first try
            backoff_ms = INIT_BACKOFF_MS; 
        } else {
            // sleep for time, then increase backup 
            usleep(backoff_ms);
            backoff_ms = min(2 * backoff_ms, MAX_BACKOFF_MS);
        }

        http_send_request(conn, url);
        http_receive_response_headers(conn);
        if (conn->status_code != 200) {
            fprintf(stderr, "%.3f sec: warning: %d,%d: "
                    "server returned status %d (expected 200)\n",
                    elapsed(), pa.x, pa.y, conn->status_code);
        } else {
            // TODO: could block right here if we receive an immediate stop
            // command, but we're not hitting that problem
            // lock last_thread_finished_mutex
            pthread_mutex_lock(&last_thread_finished_mutex);
            last_thread_finished = true;
            pthread_mutex_unlock(&last_thread_finished_mutex);
            // signal
            pthread_cond_signal(&last_thread_finished_cond_var);
        }

        http_receive_response_body(conn);
        int wait_time = -1;
        // scan the message from teh server
        int cool_down_flag = sscanf(conn->buf, "+%d STOP", &wait_time);
        // ensure that this is in fact a wait message
        if (cool_down_flag && wait_time != -1) {
            // in this case, the server is asking up to cool down
            // lock this and sleep
            pthread_mutex_lock(&request_mutex);
            usleep(wait_time * 1000); // convert from millisecond to microseconds
            pthread_mutex_unlock(&request_mutex);
        }
        double result = strtod(conn->buf, NULL);
        if (result < 0) {
            fprintf(stderr, "%.3f sec: server returned error: %s\n",
                    elapsed(), http_truncate_response(conn));

            if (conn->cstate == cstate_broken) {
                http_close(conn);
                exit(1);
            }
        }
        
        // determine if move was successfully sent 
        move_success = conn->status_code != -1;

        if (move_success && conn->cstate == cstate_idle) {
            assert(conn->cstate == cstate_idle);
            // recycle this connection since we are done in this thread
            push_connection(conn);
        } else {
            // close that connection
            assert(conn->cstate == cstate_broken);
            http_close(conn);
            // create new connection
            conn = http_connect(pong_addr);
        }
    } while (!move_success);
   
    // signal the main thread to continue
    // XXX The handout code uses polling and unsafe concurrent access to a
    // global variable. For full credit, replace this with pthread
    // synchronization objects (in Phase 3).
    // move_done = 1;
    // and exit!
    pthread_exit(NULL);
}


// usage()
//    Explain how pong61 should be run.
static void usage(void) {
    fprintf(stderr, "Usage: ./pong61 [-h HOST] [-p PORT] [USER]\n");
    exit(1);
}


// main(argc, argv)
//    The main loop.
int main(int argc, char** argv) {
    // parse arguments
    int ch, nocheck = 0, fast = 0;
    while ((ch = getopt(argc, argv, "nfh:p:u:")) != -1) {
        if (ch == 'h') {
            pong_host = optarg;
        } else if (ch == 'p') {
            pong_port = optarg;
        } else if (ch == 'u') {
            pong_user = optarg;
        } else if (ch == 'n') {
            nocheck = 1;
        } else if (ch == 'f') {
            fast = 1;
        } else {
            usage();
        }
    }
    if (optind == argc - 1) {
        pong_user = argv[optind];
    } else if (optind != argc) {
        usage();
    }

    // look up network address of pong server
    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_NUMERICSERV;
    int r = getaddrinfo(pong_host, pong_port, &hints, &pong_addr);
    if (r != 0) {
        fprintf(stderr, "problem looking up %s: %s\n",
                pong_host, gai_strerror(r));
        exit(1);
    }

    // reset pong board and get its dimensions
    int width, height, delay = 100000;
    {
        http_connection* conn = http_connect(pong_addr);
        if (!nocheck && !fast) {
            http_send_request(conn, "reset");
        } else {
            char buf[256];
            sprintf(buf, "reset?nocheck=%d&fast=%d", nocheck, fast);
            http_send_request(conn, buf);
        }
        http_receive_response_headers(conn);
        http_receive_response_body(conn);
        int nchars;
        if (conn->status_code != 200
            || sscanf(conn->buf, "%d %d %n", &width, &height, &nchars) < 2
            || width <= 0 || height <= 0) {
            fprintf(stderr, "bad response to \"reset\" RPC: %d %s\n",
                    conn->status_code, http_truncate_response(conn));
            exit(1);
        }
        (void) sscanf(conn->buf + nchars, "%d", &delay);
        http_close(conn);
    }
    // measure future times relative to this moment
    start_time = tstamp();

    // print display URL
    printf("Display: http://%s:%s/%s/%s\n",
           pong_host, pong_port, pong_user,
           nocheck ? " (NOCHECK mode)" : "");

    // play game
    init_connections();
    // flag for previous header finishing
    pthread_mutex_init(&last_thread_finished_mutex, NULL);
    // condition var for last thread finishing
    pthread_cond_init(&last_thread_finished_cond_var, NULL);
    // initialize request sending mutex
    pthread_mutex_init(&request_mutex, NULL);
    last_thread_finished = true;
    int x = 0, y = 0, dx = 1, dy = 1;
    while (1) {
        // create a new thread to handle the next position
        pong_args* pa = malloc(sizeof(pong_args));
        pa->x = x;
        pa->y = y;
        pthread_t pt;

        // wait on the ability to create new thread
        pthread_mutex_lock(&last_thread_finished_mutex); // lock
        while (!last_thread_finished) { // check condition
            pthread_cond_wait(&last_thread_finished_cond_var, &last_thread_finished_mutex); // wait on cond var
        }
        last_thread_finished = false;
        pthread_mutex_unlock(&last_thread_finished_mutex);
        
        /*bool no_more_connections = true;*/
        http_connection* next_conn = NULL;
        while ((next_conn = pop_connection()) == NULL) {
            usleep(CONNECTIONS_SLEEP_TIME);
        }

        // we now have an available connection
        pa->conn = next_conn;
        r = pthread_create(&pt, NULL, pong_thread, pa);
        if (r != 0) {
            fprintf(stderr, "%.3f sec: pthread_create: %s\n",
                    elapsed(), strerror(r));
            exit(1);
        }

        // wait until that thread signals us to continue
        // XXX The handout code uses polling and unsafe concurrent access to a
        // global variable. For full credit, replace this with pthread
        // synchronization objects.
        //

        /*while (!move_done) {*/
            /*usleep(20000); // *sort of* blocking...*/
        /*}*/
        /*move_done = 0;*/

        // update position
        x += dx;
        y += dy;
        if (x < 0 || x >= width) {
            dx = -dx;
            x += 2 * dx;
        }
        if (y < 0 || y >= height) {
            dy = -dy;
            y += 2 * dy;
        }

        // wait 0.1sec
        usleep(delay);
    }
}


// HTTP PARSING

// http_process_response_headers(conn)
//    Parse the response represented by `conn->buf`. Returns 1
//    if more header data remains to be read, 0 if all headers
//    have been consumed.
static int http_process_response_headers(http_connection* conn) {
    size_t i = 0;
    while ((conn->cstate == cstate_waiting || conn->cstate == cstate_headers)
           && i + 2 <= conn->len) {
        if (conn->buf[i] == '\r' && conn->buf[i+1] == '\n') {
            conn->buf[i] = 0;
            if (conn->cstate == cstate_waiting) {
                int minor;
                if (sscanf(conn->buf, "HTTP/1.%d %d",
                           &minor, &conn->status_code) == 2) {
                    conn->cstate = cstate_headers;
                } else {
                    conn->cstate = cstate_broken;
                }
            } else if (i == 0) {
                conn->cstate = cstate_body;
            } else if (strncasecmp(conn->buf, "Content-Length: ", 16) == 0) {
                conn->content_length = strtoul(conn->buf + 16, NULL, 0);
                conn->has_content_length = 1;
            }
            // We just consumed a header line (i+2) chars long.
            // Move the rest of the data down, including terminating null.
            memmove(conn->buf, conn->buf + i + 2, conn->len - (i + 2) + 1);
            conn->len -= i + 2;
            i = 0;
        } else {
            ++i;
        }
    }

    if (conn->eof) {
        conn->cstate = cstate_broken;
    }
    return conn->cstate == cstate_waiting || conn->cstate == cstate_headers;
}


// http_check_response_body(conn)
//    Returns 1 if more response data should be read into `conn->buf`,
//    0 if the connection is broken or the response is complete.
static int http_check_response_body(http_connection* conn) {
    if (conn->cstate == cstate_body
        && (conn->has_content_length || conn->eof)
        && conn->len >= conn->content_length) {
        conn->cstate = cstate_idle;
    }
    if (conn->eof && conn->cstate == cstate_idle) {
        conn->cstate = cstate_closed;
    } else if (conn->eof) {
        conn->cstate = cstate_broken;
    }
    return conn->cstate == cstate_body;
}
