#include "sh61.h"
#include <string.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <stdbool.h>

#define REDIRECT_STDIN 0
#define REDIRECT_STDOUT 1
#define REDIRECT_STDERR 2


// struct command
//    Data structure describing a command. Add your own stuff.

typedef struct command command;
struct command {
    int argc;      // number of arguments
    char** argv;   // arguments, terminated by NULL
    pid_t pid;     // process ID running this command, -1 if none
    bool in_background;
    command* next;
    command* prev;
    bool is_conditional;
    char conditional_requirement;
    char exit_status;
    bool command_stop;
    bool pipe_output;
    bool final_instr;
    bool read_flag;
    bool write_flag;
    bool error_flag;
    char* read_file;
    char* write_file;
    char* error_file;
    bool is_cd;
};


// command_alloc()
//    Allocate and return a new command structure.

static command* command_alloc(void) {
    command* c = (command*) malloc(sizeof(command));
    c->argc = 0;
    c->argv = NULL;
    c->pid = -1;
    c->in_background = false;
    c->next = NULL;
    c->prev = NULL;
    c->is_conditional = false;
    c->conditional_requirement = -1;
    c->exit_status = -1;
    c->command_stop = false;
    c->pipe_output = false;
    c->final_instr = false;
    c->read_flag = false;
    c->write_flag = false;
    c->error_flag = false;
    c->read_file = NULL;
    c->write_file = NULL;
    c->error_file = NULL;
    c->is_cd = false;
    return c;
}


// command_free(c)
//    Free command structure `c`, including all its words.

static void command_free(command* c) {
    for (int i = 0; i != c->argc; ++i) {
        free(c->argv[i]);
    }
    free(c->read_file);
    free(c->write_file);
    free(c->error_file);
    free(c->argv);
    free(c);
}


// command_append_arg(c, word)
//    Add `word` as an argument to command `c`. This increments `c->argc`
//    and augments `c->argv`.

static void command_append_arg(command* c, char* word) {
    c->argv = (char**) realloc(c->argv, sizeof(char*) * (c->argc + 2));
    c->argv[c->argc] = word;
    c->argv[c->argc + 1] = NULL;
    ++c->argc;
}


// get_num_pipes(c)
//   Find the number of consecutive piped commands.
//   i.e. "echo Pipe | wc -c | echo" should return 2
int get_num_pipes(command* c) {
    int num_pipes = 0;
    while (c->pipe_output) {
        ++num_pipes;
        c = c->next;
    }
    return num_pipes;
}

// handle_open_call(fd)
//   Prints error message and exits if we failed to open a file.
void handle_open_call(int fd) {
    if (fd == -1) {
        fprintf(stderr, "%s\n", strerror(errno));
        _exit(EXIT_FAILURE);
    }
    return;
}

// COMMAND EVALUATION

// start_command(c, pgid)
//    Start the single command indicated by `c`. Sets `c->pid` to the child
//    process running the command, and returns `c->pid`.
//
//    PART 1: Fork a child process and run the command using `execvp`.
//    PART 5: Set up a pipeline if appropriate. This may require creating a
//       new pipe (`pipe` system call), and/or replacing the child process's
//       standard input/output with parts of the pipe (`dup2` and `close`).
//       Draw pictures!
//    PART 7: Handle redirections.
//    PART 8: The child process should be in the process group `pgid`, or
//       its own process group (if `pgid == 0`). To avoid race conditions,
//       this will require TWO calls to `setpgid`.

pid_t start_command(command* c, pid_t pgid) {
    // Your code here!
    // handle piping here
    bool piping = false;
    // number of physical '|' characters
    int num_pipes = get_num_pipes(c);
    // need an input and output for each physical pipe
    // add one to the end so we don't have a 0 length array
    int pipes[(num_pipes * 2) + 1];
    int current_pipe = 0;
    if (num_pipes > 0) {
        // set up pipes
        piping = true;
        for (int i = 0; i < num_pipes * 2; i += 2) {
            if (pipe(pipes + i) < 0) {
                _exit(EXIT_FAILURE);
            }
        }
    }

    // continue until we execute a command that doesn't pipe its output
    while (true) {
        /*printf("in start_command %s %s\n", c->argv[0], c->argv[1]);*/
        // fork parent process
        if ((c->pid = fork()) < 0) {
            // failed to fork
            _exit(EXIT_FAILURE);
        } else if (c->pid == 0) {
            // child process
            // set pgid
            setpgid(c->pid, pgid);
            if (piping) {
                // get correct input/output pipe
                int pipe_slot = 2 * current_pipe;
                if (current_pipe == 0) {
                    // only write
                    dup2(pipes[pipe_slot + 1], 1);
                } else if (current_pipe == num_pipes) {
                    // only read
                    dup2(pipes[pipe_slot - 2], 0);
                } else {
                    // do both
                    // read
                    dup2(pipes[pipe_slot - 2], 0);
                    // write
                    dup2(pipes[pipe_slot + 1], 1);
                }
                // close all pipes now that we got the relevant mapping
                for (int i = 0; i < num_pipes * 2; ++i) {
                    close(pipes[i]);
                }
            }
            // handle redirections here
            if (c->read_flag) {
                int fd;
                fd = open(c->read_file, O_RDONLY);
                // check for success, error and exit if not
                handle_open_call(fd);
                // modify stdin
                dup2(fd, REDIRECT_STDIN);
                close(fd);
            }
            if (c->write_flag) {
                int fd;
                // read, write permissions, create file if doesn't
                // already exist
                fd = open(c->write_file, O_WRONLY | O_CREAT, 0666);
                handle_open_call(fd);
                // modify stdout
                dup2(fd, REDIRECT_STDOUT);
                close(fd);
            }
            if (c->error_flag) {
                int fd;
                fd = open(c->error_file, O_WRONLY | O_CREAT, 0666);
                handle_open_call(fd);
                // modify stderr
                dup2(fd, REDIRECT_STDERR);
                close(fd);
            }

            // execute desired program
            if (execvp(c->argv[0], c->argv) == -1) {
                // failed to execute script
                _exit(EXIT_FAILURE);
            }
        } else {
            /*printf("CHILD pid %d\n", c->pid);*/
            // in parent process
            // set child pgid
            setpgid(c->pid, c->pid);
            // stop if we executed a command that doesn't pipe its output
            if (!c->pipe_output) {
                break;
            } else {
                // increment which physical pipe we are on
                ++current_pipe;
                c = c->next;
            }
        }
    }
    // close all the pipes, which the parent doesn't need
    for (int i = 0; i < num_pipes * 2; ++i) {
        close(pipes[i]);
    }
    /*printf("child pid before return %d\n", c->pid);*/
    return c->pid;
}


// run_list(c)
//    Run the command list starting at `c`.
//
//    PART 1: Start the single command `c` with `start_command`,
//        and wait for it to finish using `waitpid`.
//    The remaining parts may require that you change `struct command`
//    (e.g., to track whether a command is in the background)
//    and write code in run_list (or in helper functions!).
//    PART 2: Treat background commands differently.
//    PART 3: Introduce a loop to run all commands in the list.
//    PART 4: Change the loop to handle conditionals.
//    PART 5: Change the loop to handle pipelines. Start all processes in
//       the pipeline in parallel. The status of a pipeline is the status of
//       its LAST command.
//    PART 8: - Choose a process group for each pipeline.
//       - Call `claim_foreground(pgid)` before waiting for the pipeline.
//       - Call `claim_foreground(0)` once the pipeline is complete.

void run_list(command* c) {
    // start child processes
    // remember the original thread so that it only ever calls "claim_foreground"
    pid_t foreground_pid = getpid();
    while (c) {
        if (c->is_cd) {
            // never leave parent for a cd, we want the foreground process
            // to be in the new directory so this isn't something we can do in the background
            if (chdir(c->argv[0]) == 0) {
                c->exit_status = 0;
            } else {
                c->exit_status = 1;
            }
            c = c->next;
            continue;
        } else if (c->argc) {
            // conditionals
            if (c->is_conditional) {
                /*printf("conditional\n");*/
                if (c->prev && c->prev->exit_status != c->conditional_requirement) {
                    /*printf("prev command: %s, %s\n", c->prev->argv[0], c->prev->argv[1]);*/
                    /*printf("prev status %d needed %d\n", c->prev->exit_status, c->conditional_requirement);*/
                    /*printf("didnt meet conditional %s %s\n", c->argv[0], c->argv[1]);*/
                    // pass the exit status along
                    c->exit_status = c->prev->exit_status;
                    c = c->next;
                    continue;
                }
            }

            pid_t child_pid;

            if (c->in_background) {
                // continue immediately if running in background
                /*printf("background\n");*/
                pid_t bg_child_pid;
                // fork parent process
                if ((bg_child_pid = fork()) < 0) {
                    // failed to fork
                    _exit(EXIT_FAILURE);
                } else if (bg_child_pid == 0) {
                    // in child process
                    // modify commands, truncate at command stop (inclusive)
                    // background should get its own
                    setpgid(0, 0);
                    command* seek = c;
                    while (seek && !seek->command_stop) {
                        // these are now running in the foreground of the background
                        seek->in_background = false;
                        seek = seek->next;
                    }
                    // this needs to be the final thing executed before exiting
                    seek->in_background = false;
                    seek->final_instr = true;
                    seek->next = NULL;
                } else {
                    /*printf("CHILD pid %d\n", bg_child_pid);*/
                    // in the parent process
                    // modify commands, jump beyond next command stop
                    while (c && !c->command_stop) {
                        c = c->next;
                    }
                    c = c->next;
                    continue;
                }
            }

            // start command
            child_pid = start_command(c, 0);
            // progress to next element that doesn't pipe its output, which
            // is the command we wait for
            while (c->pipe_output) {
                c = c->next;
            }
            // wait for operation to complete
            int status;
            if (foreground_pid == getpid()) {
                // only claim the foreground if you were the initial pid, since
                // everything else is a background
                claim_foreground(child_pid);
            }
            while (waitpid(child_pid, &status, WNOHANG) != child_pid) {
                ;
            }
            if (WIFEXITED(status)) {
                /*printf("pid %d\n", child_pid);*/
                /*printf("exited %s %s\n", c->argv[0], c->argv[1]);*/
                /*printf("status %d\n", WEXITSTATUS(status));*/
                c->exit_status = WEXITSTATUS(status);
            }
        }
        if (c->final_instr) {
            _exit(EXIT_SUCCESS);
        }
        c = c->next;
    }
    return;
}


// eval_line(c)
//    Parse the command list in `s` and run it via `run_list`.

void eval_line(const char* s) {
    int type;
    char* token;
    // Your code here!

    // build the command
    command* first_c = command_alloc();
    command* c = first_c;
    while ((s = parse_shell_token(s, &type, &token)) != NULL) {
        if (strcmp(token, "cd") == 0) {
            c->is_cd = true;
        } else if (strcmp(token, "<") == 0) {
            c->read_flag = true;
        } else if (strcmp(token, ">") == 0) {
            c->write_flag = true;
        } else if (strcmp(token, "2>") == 0) {
            c->error_flag = true;
        } else if (strcmp(token, "&&") == 0) {
            c->next = command_alloc();
            c->next->prev = c;
            c = c->next;
            c->is_conditional = true;
            c->conditional_requirement = EXIT_SUCCESS;
        } else if (strcmp(token, "||") == 0) {
            c->next = command_alloc();
            c->next->prev = c;
            c = c->next;
            c->is_conditional = true;
            c->conditional_requirement = EXIT_FAILURE;
        } else if (*token == '&') {
            // mark previous items as in the background
            command* prevs = c;
            while (prevs && !prevs->command_stop) {
                prevs->in_background = true;
                prevs = prevs->prev;
            }
            c->command_stop = true;
            // start new one
            c->next = command_alloc();
            c->next->prev = c;
            c = c->next;
        } else if (*token == '|') {
            c->pipe_output = true;
            // start new one
            c->next = command_alloc();
            c->next->prev = c;
            c = c->next;
        } else if (*token == ';') {
            c->command_stop = true;
            // start new one
            c->next = command_alloc();
            c->next->prev = c;
            c = c->next;
        } else {
            if (c->read_flag && c->read_file == NULL) {
                // copy name of the file
                c->read_file = malloc(sizeof(char) * strlen(token) + 1);
                strcpy(c->read_file, token);
            } else if (c->write_flag && c->write_file == NULL) {
                c->write_file = malloc(sizeof(char) * strlen(token) + 1);
                strcpy(c->write_file, token);
            } else if (c->error_flag && c->error_file == NULL) {
                c->error_file = malloc(sizeof(char) * strlen(token) + 1);
                strcpy(c->error_file, token);
            } else {
                command_append_arg(c, token);
            }
        }
    }

    // for examining the command chain
    /*c = first_c;*/
    /*while (c) {*/
        /*printf("command: %s %s, command_stop: %d, pipe_output: %d", c->argv[0], c->argv[1], c->command_stop, c->pipe_output);*/
        /*printf(" -> ");*/
        /*c = c->next;*/
    /*}*/
    /*printf("finished\n");*/
    /*printf("\n");*/

    // attach to front of list
    c = first_c;

    // execute it
    if (c->argc) {
        run_list(c);
    }
    // free all commands
    while(c) {
        command* old_c = c;
        c = c->next;
        command_free(old_c);
    }
}

// this doesn't actually need to do anything
// beside catch the signal so we don't crash
void signal_handler(int signal) {
    (void) signal;
    return;
}

int main(int argc, char* argv[]) {
    // set up our signal handler
    set_signal_handler(SIGINT, signal_handler);
    FILE* command_file = stdin;
    int quiet = 0;

    // Check for '-q' option: be quiet (print no prompts)
    if (argc > 1 && strcmp(argv[1], "-q") == 0) {
        quiet = 1;
        --argc, ++argv;
    }

    // Check for filename option: read commands from file
    if (argc > 1) {
        command_file = fopen(argv[1], "rb");
        if (!command_file) {
            perror(argv[1]);
            exit(1);
        }
    }

    // - Put the shell into the foreground
    // - Ignore the SIGTTOU signal, which is sent when the shell is put back
    //   into the foreground
    claim_foreground(0);
    set_signal_handler(SIGTTOU, SIG_IGN);

    char buf[BUFSIZ];
    int bufpos = 0;
    int needprompt = 1;

    while (!feof(command_file)) {
        // foreground goes to the shell
        claim_foreground(0);
        // Print the prompt at the beginning of the line
        if (needprompt && !quiet) {
            printf("sh61[%d]$ ", getpid());
            fflush(stdout);
            needprompt = 0;
        }

        // Read a string, checking for error or EOF
        if (fgets(&buf[bufpos], BUFSIZ - bufpos, command_file) == NULL) {
            if (ferror(command_file) && errno == EINTR) {
                // just want to issue the prompt again
                needprompt = 1;
                printf("\n");
                // ignore EINTR errors
                clearerr(command_file);
                buf[bufpos] = 0;
            } else {
                if (ferror(command_file)) {
                    perror("sh61");
                }
                break;
            }
        }

        // If a complete command line has been provided, run it
        bufpos = strlen(buf);
        if (bufpos == BUFSIZ - 1 || (bufpos > 0 && buf[bufpos - 1] == '\n')) {
            eval_line(buf);
            bufpos = 0;
            needprompt = 1;
        }

        // Handle zombie processes and/or interrupt requests
        // Your code here!
        // pick up any zombie child processes (their pid is above 0 if they exist)
        while (waitpid((pid_t) -1, 0, WNOHANG) > 0) {
            ;
        }
    }

    return 0;
}
