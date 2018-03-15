#include "kernel.h"
#include "lib.h"

// kernel.c
//
//    This is the kernel.


// INITIAL PHYSICAL MEMORY LAYOUT
//
//  +-------------- Base Memory --------------+
//  v                                         v
// +-----+--------------------+----------------+--------------------+---------/
// |     | Kernel      Kernel |       :    I/O | App 1        App 1 | App 2
// |     | Code + Data  Stack |  ...  : Memory | Code + Data  Stack | Code ...
// +-----+--------------------+----------------+--------------------+---------/
// 0  0x40000              0x80000 0xA0000 0x100000             0x140000
//                                             ^
//                                             | \___ PROC_SIZE ___/
//                                      PROC_START_ADDR

#define PROC_SIZE 0x40000       // initial state only

static proc processes[NPROC];   // array of process descriptors
                                // Note that `processes[0]` is never used.
proc* current;                  // pointer to currently executing proc

int8_t currently_allocating_for; // id of process we are currently allocating page tables for

#define HZ 100                  // timer interrupt frequency (interrupts/sec)
static unsigned ticks;          // # timer interrupts so far

void schedule(void);
void run(proc* p) __attribute__((noreturn));


// PAGEINFO
//
//    The pageinfo[] array keeps track of information about each physical page.
//    There is one entry per physical page.
//    `pageinfo[pn]` holds the information for physical page number `pn`.
//    You can get a physical page number from a physical address `pa` using
//    `PAGENUMBER(pa)`. (This also works for page table entries.)
//    To change a physical page number `pn` into a physical address, use
//    `PAGEADDRESS(pn)`.
//
//    pageinfo[pn].refcount is the number of times physical page `pn` is
//      currently referenced. 0 means it's free.
//    pageinfo[pn].owner is a constant indicating who owns the page.
//      PO_KERNEL means the kernel, PO_RESERVED means reserved memory (such
//      as the console), and a number >=0 means that process ID.
//
//    pageinfo_init() sets up the initial pageinfo[] state.

typedef struct physical_pageinfo {
    int8_t owner;
    int8_t refcount;
} physical_pageinfo;

static physical_pageinfo pageinfo[PAGENUMBER(MEMSIZE_PHYSICAL)];

typedef enum pageowner {
    PO_FREE = 0,                // this page is free
    PO_RESERVED = -1,           // this page is reserved memory
    PO_KERNEL = -2              // this page is used by the kernel
} pageowner_t;

static void pageinfo_init(void);


// Memory functions

void check_virtual_memory(void);
void memshow_physical(void);
void memshow_virtual(x86_64_pagetable* pagetable, const char* name);
void memshow_virtual_animate(void);


// kernel(command)
//    Initialize the hardware and processes and start running. The `command`
//    string is an optional string passed from the boot loader.

static void process_setup(pid_t pid, int program_number);

void kernel(const char* command) {
    hardware_init();
    pageinfo_init();
    console_clear();
    timer_init(HZ);

    // Set up process descriptors
    memset(processes, 0, sizeof(processes));
    for (pid_t i = 0; i < NPROC; i++) {
        processes[i].p_pid = i;
        processes[i].p_state = P_FREE;
    }

    if (command && strcmp(command, "fork") == 0) {
        process_setup(1, 4);
    } else if (command && strcmp(command, "forkexit") == 0) {
        process_setup(1, 5);
    } else {
        for (pid_t i = 1; i <= 4; ++i) {
            process_setup(i, i - 1);
        }
    }

    // Switch to the first process using run()
    run(&processes[1]);
}

// find_empty_physical_page(void)
//    Find the first unused physical page and return its page number (index)
int find_empty_physical_page(void) {
    // find empty page using pageinfo
    int num_pages = PAGENUMBER(MEMSIZE_PHYSICAL);
    for (int i = 0; i < num_pages; ++i) {
        if (pageinfo[i].refcount == 0) {
            return i;
        }
    }
    return -1;
}


// allocator(void)
//    Allocate and return a pointer to a new page table
x86_64_pagetable* allocator(void) {
    x86_64_pagetable* free_pagetable = NULL;
    // find empty physical page
    int free_page_index = find_empty_physical_page();
    if (free_page_index != -1) {
        // free address, move pagetable here
        free_pagetable = (x86_64_pagetable*) PAGEADDRESS(free_page_index);
        // increment refcount
        ++pageinfo[free_page_index].refcount;
        // assign the owner to the current process
        pageinfo[free_page_index].owner = currently_allocating_for;
        // initialize every page table entry to 0
        for (int j = 0; j < NPAGETABLEENTRIES; ++j) {
            free_pagetable->entry[j] = (uint64_t) 0;
        }
    }
    return free_pagetable;
}

// copy_pagetable(x86_64_pagetable, pagetable, int8_t owner)
//    Return a full copy of pagetable (including all mappings)
x86_64_pagetable* copy_pagetable(x86_64_pagetable* pagetable, int8_t owner){
    // currently allocating for this owner
    currently_allocating_for = owner;
    // initialize top level (level-1) page table
    x86_64_pagetable* top_level_pagetable = allocator();
    // if we failed for lack of memory
    if (top_level_pagetable == NULL) {
        return NULL;
    }
    // copy the provided page table's virtual memory into the new pagetable
    // by accessing the physical location of the virtual memory and copying
    // the mapping using virtual_memory_map
    for (int i = 0; i < MEMSIZE_VIRTUAL; i += PAGESIZE) {
        vamapping vmap = virtual_memory_lookup(pagetable, i);
        if (vmap.pa != (uintptr_t) -1) {
            // this address is mapped, so copy
            virtual_memory_map(top_level_pagetable, i, vmap.pa, PAGESIZE, vmap.perm, allocator);
        }
    }
    return top_level_pagetable;
}

// free process and all its data/metadata
// process is the process to free, and data boundary says how much of the
// virtual memory space we need to free. this is for the case where we
// try to fork, get halfway through, then realize we don't have enough memory
// we only want to free data that we've starting mapping, otherwise we will
// have an inconsistent refcount
void free_process_fn(proc* process, int data_boundary) {
    log_printf("freeing process: %d\n", process->p_pid);
    // remove the all the process's references to physical memory
    for (int i = PROC_START_ADDR; i < data_boundary; i += PAGESIZE) {
        vamapping vmap = virtual_memory_lookup(process->p_pagetable, i);
        if (vmap.pn != -1) {
            // clean up references to this physical memory
            --pageinfo[vmap.pn].refcount;
            if (pageinfo[vmap.pn].owner == process->p_pid) {
                // we are the owner
                if (pageinfo[vmap.pn].refcount == 0) {
                    // we held the last reference, this phys memory is now free
                    pageinfo[vmap.pn].owner = PO_FREE;
                } else {
                    // we didn't hold the last reference, i.e. this was a read
                    // only block and another process was also referencing
                    // this
                    // iterate through the extant processes, find one that
                    // holds a reference to this page, make it the new owner
                    for (int p = 0; p < NPROC; ++p) {
                        proc* current_proc = &processes[p];
                        // don't check the proc we are freeing
                        if (current_proc != process && current_proc->p_state == P_RUNNABLE) {
                            // see if it has a reference to this page
                            vamapping second_vmap = virtual_memory_lookup(current_proc->p_pagetable, i);
                            if (second_vmap.pn != -1) {
                                // make this process the owner
                                pageinfo[vmap.pn].owner = current_proc->p_pid;
                                // don't need to continue anymore
                                break;
                            }
                        }
                    }
                }
            } else {
                if (pageinfo[vmap.pn].refcount == 0) {
                    // it's a bug if we hit this case, we should never hold
                    // the last reference to a physical page if we aren't the owner
                    log_printf("BUG, owner: %d, current_proc: %d\n", pageinfo[vmap.pn].owner, process->p_pid);
                    log_printf("currently running procs\n");
                    for (int p = 0; p < NPROC; ++p) {
                        proc* current_proc = &processes[p];
                        // don't check the proc we are freeing
                        if (current_proc->p_state == P_RUNNABLE) {
                            log_printf("running proc: %d\n", current_proc->p_pid);
                        }
                    }
                    pageinfo[vmap.pn].owner = PO_FREE;
                }
            }
        }
    }
    for (int i = 0; i < MEMSIZE_PHYSICAL; i += PAGESIZE) {
        // these should only ever have a single reference
        int pn = PAGENUMBER(i);
        if (pageinfo[pn].owner == process->p_pid) {
            pageinfo[pn].refcount = 0;
            pageinfo[pn].owner = PO_FREE;
        }
    }
    processes[process->p_pid].p_state = P_FREE;
}

// fork
int fork() {
    log_printf("forking this process: %d\n", current->p_pid);
    // find free processes slot
    int free_process = -1;
    for (int i = 1; i < NPROC; ++i) {
        if (processes[i].p_state == P_FREE) {
            free_process = i;
            processes[free_process].p_state = P_RUNNABLE;
            processes[free_process].p_registers = current->p_registers;
            processes[free_process].p_registers.reg_rax = 0;
            break;
        }
    }
    if (free_process != -1) {
        // copy the current pagetable
        currently_allocating_for = free_process;
        x86_64_pagetable* new_pt = copy_pagetable(current->p_pagetable, free_process);
        // if this failed, we don't have enough memory, back track
        if (new_pt == NULL) {
            log_printf("making new pt failed\n");
            // set this process as free
            processes[free_process].p_state = P_FREE;
            // return -1
            return -1;
        }
        // copy this pagetable into the process
        processes[free_process].p_pagetable = new_pt;
        // copy process data
        // iterate through all process addresses
        for (int virtual_mem = PROC_START_ADDR; virtual_mem < MEMSIZE_VIRTUAL; virtual_mem += PAGESIZE) {
            // lookup the mapping information
            vamapping vmap = virtual_memory_lookup(current->p_pagetable, virtual_mem);
            if (vmap.pn != -1 && (vmap.perm & (PTE_W | PTE_U | PTE_P)) == (PTE_W | PTE_U | PTE_P)) {
                // copy this data
                int free_page = find_empty_physical_page();
                if (free_page == -1) {
                    log_printf("copying writable data failed\n");
                    // free process
                    free_process_fn(&processes[free_process], virtual_mem);
                    // return -1
                    return -1;
                }
                uint64_t free_page_addr = PAGEADDRESS(free_page);
                memcpy((void*) free_page_addr, (void*) vmap.pa, PAGESIZE);
                assign_physical_page(free_page_addr, free_process);
                virtual_memory_map(new_pt, virtual_mem, free_page_addr, PAGESIZE, vmap.perm, allocator);
            } else if (vmap.pn != -1 && (vmap.perm & (PTE_U | PTE_P)) == (PTE_U | PTE_P)) {
                // read only memory, don't need to copy it
                // add this to the virtual memory map, update pageinfo
                int success = virtual_memory_map(new_pt, virtual_mem, vmap.pa, PAGESIZE, vmap.perm, allocator);
                if (success == -1) {
                    log_printf("failed to allocate\n");
                    // free process
                    free_process_fn(&processes[free_process], virtual_mem);
                    // return -1
                    return -1;
                }
                ++pageinfo[vmap.pn].refcount;
            }
        }
    }
    return free_process;
}


// process_setup(pid, program_number)
//    Load application program `program_number` as process number `pid`.
//    This loads the application's code and data into memory, sets its
//    %rip and %rsp, gives it a stack page, and marks it as runnable.

void process_setup(pid_t pid, int program_number) {
    log_printf("calling process_setup: %d, %d\n", pid, program_number);
    process_init(&processes[pid], 0);
    // each process gets its own pagetable
    processes[pid].p_pagetable = copy_pagetable(kernel_pagetable, pid);
    // remove access to anything above PROC_START_ADDR
    // iterate above PROC_START_ADDR, one page at a time, remap that
    // memory with different permissions
    for (int virtual_mem = PROC_START_ADDR; virtual_mem < MEMSIZE_VIRTUAL; virtual_mem += PAGESIZE) {
        vamapping vmap = virtual_memory_lookup(processes[pid].p_pagetable, virtual_mem);
        if (vmap.pa != (uintptr_t) -1) {
            // this address is mapped, so update permission
            // commented out ability to let the kernel access these memory locations as well
            /*virtual_memory_map(processes[pid].p_pagetable, virtual_mem, vmap.pa, PAGESIZE, PTE_P | PTE_W, allocator);*/
            virtual_memory_map(processes[pid].p_pagetable, virtual_mem, vmap.pa, PAGESIZE, 0, allocator);
        }
    }
    int r = program_load(&processes[pid], program_number, NULL);
    assert(r >= 0);
    processes[pid].p_registers.reg_rsp = MEMSIZE_VIRTUAL;
    uintptr_t stack_page = processes[pid].p_registers.reg_rsp - PAGESIZE;
    int empty_phys_page = find_empty_physical_page();
    assign_physical_page(PAGEADDRESS(empty_phys_page), pid);
    virtual_memory_map(processes[pid].p_pagetable, stack_page, PAGEADDRESS(empty_phys_page),
                       PAGESIZE, PTE_P | PTE_W | PTE_U, allocator);
    processes[pid].p_state = P_RUNNABLE;
}


// assign_physical_page(addr, owner)
//    Allocates the page with physical address `addr` to the given owner.
//    Fails if physical page `addr` was already allocated. Returns 0 on
//    success and -1 on failure. Used by the program loader.

int assign_physical_page(uintptr_t addr, int8_t owner) {
    if ((addr & 0xFFF) != 0
        || addr >= MEMSIZE_PHYSICAL
        || pageinfo[PAGENUMBER(addr)].refcount != 0) {
        return -1;
    } else {
        pageinfo[PAGENUMBER(addr)].refcount = 1;
        pageinfo[PAGENUMBER(addr)].owner = owner;
        return 0;
    }
}


// exception(reg)
//    Exception handler (for interrupts, traps, and faults).
//
//    The register values from exception time are stored in `reg`.
//    The processor responds to an exception by saving application state on
//    the kernel's stack, then jumping to kernel assembly code (in
//    k-exception.S). That code saves more registers on the kernel's stack,
//    then calls exception().
//
//    Note that hardware interrupts are disabled whenever the kernel is running.

void exception(x86_64_registers* reg) {
    // Copy the saved registers into the `current` process descriptor
    // and always use the kernel's page table.
    current->p_registers = *reg;
    // why does this assert fail otherwise?
    assert(virtual_memory_lookup(kernel_pagetable, (uintptr_t) kernel_pagetable).pa == (uintptr_t) kernel_pagetable);
    set_pagetable(kernel_pagetable);

    // It can be useful to log events using `log_printf`.
    // Events logged this way are stored in the host's `log.txt` file.
    /*log_printf("proc %d: exception %d\n", current->p_pid, reg->reg_intno);*/

    // Show the current cursor location and memory state
    // (unless this is a kernel fault).
    console_show_cursor(cursorpos);
    if (reg->reg_intno != INT_PAGEFAULT || (reg->reg_err & PFERR_USER)) {
        check_virtual_memory();
        memshow_physical();
        memshow_virtual_animate();
    }

    // If Control-C was typed, exit the virtual machine.
    check_keyboard();

    // Actually handle the exception.
    switch (reg->reg_intno) {

    case INT_SYS_PANIC:
        panic(NULL);
        break;                  // will not be reached

    case INT_SYS_GETPID:
        current->p_registers.reg_rax = current->p_pid;
        break;

    case INT_SYS_YIELD:
        schedule();
        break;                  /* will not be reached */

    case INT_SYS_PAGE_ALLOC: {
        uintptr_t addr = current->p_registers.reg_rdi;
        // no longer need
        /*int r = assign_physical_page(addr, current->p_pid);*/
        int r = find_empty_physical_page();
        if (r >= 0) {
            // record allocation owner and refcount in pageinfo
            assign_physical_page(PAGEADDRESS(r), current->p_pid);
            // ADDED: only give kernel access if below the process memory addresses
            if (addr < PROC_START_ADDR) {
                virtual_memory_map(current->p_pagetable, addr, PAGEADDRESS(r),
                                   PAGESIZE, PTE_P | PTE_W, NULL);
            } else {
                virtual_memory_map(current->p_pagetable, addr, PAGEADDRESS(r),
                                   PAGESIZE, PTE_P | PTE_W | PTE_U, NULL);
            }
        }
        current->p_registers.reg_rax = r;
        break;
    }

    case INT_TIMER:
        ++ticks;
        schedule();
        break;                  /* will not be reached */

    case INT_PAGEFAULT: {
        // Analyze faulting address and access type.
        uintptr_t addr = rcr2();
        const char* operation = reg->reg_err & PFERR_WRITE
                ? "write" : "read";
        const char* problem = reg->reg_err & PFERR_PRESENT
                ? "protection problem" : "missing page";

        if (!(reg->reg_err & PFERR_USER)) {
            panic("Kernel page fault for %p (%s %s, rip=%p)!\n",
                  addr, operation, problem, reg->reg_rip);
        }
        console_printf(CPOS(24, 0), 0x0C00,
                       "Process %d page fault for %p (%s %s, rip=%p)!\n",
                       current->p_pid, addr, operation, problem, reg->reg_rip);
        current->p_state = P_BROKEN;
        break;
    }

    case INT_SYS_FORK: {
        // farm out to fork function
        current->p_registers.reg_rax = fork();
        break;
    }

    case INT_SYS_EXIT: {
        free_process_fn(current, MEMSIZE_VIRTUAL);
        break;
    }

    default:
        panic("Unexpected exception %d!\n", reg->reg_intno);
        break;                  /* will not be reached */

    }

    // Return to the current process (or run something else).
    if (current->p_state == P_RUNNABLE) {
        run(current);
    } else {
        schedule();
    }
}


// schedule
//    Pick the next process to run and then run it.
//    If there are no runnable processes, spins forever.

void schedule(void) {
    pid_t pid = current->p_pid;
    while (1) {
        pid = (pid + 1) % NPROC;
        if (processes[pid].p_state == P_RUNNABLE) {
            run(&processes[pid]);
        }
        // If Control-C was typed, exit the virtual machine.
        check_keyboard();
    }
}


// run(p)
//    Run process `p`. This means reloading all the registers from
//    `p->p_registers` using the `popal`, `popl`, and `iret` instructions.
//
//    As a side effect, sets `current = p`.

void run(proc* p) {
    assert(p->p_state == P_RUNNABLE);
    current = p;

    // Load the process's current pagetable.
    set_pagetable(p->p_pagetable);

    // This function is defined in k-exception.S. It restores the process's
    // registers then jumps back to user mode.
    exception_return(&p->p_registers);

 spinloop: goto spinloop;       // should never get here
}


// pageinfo_init
//    Initialize the `pageinfo[]` array.

void pageinfo_init(void) {
    extern char end[];

    for (uintptr_t addr = 0; addr < MEMSIZE_PHYSICAL; addr += PAGESIZE) {
        int owner;
        if (physical_memory_isreserved(addr)) {
            owner = PO_RESERVED;
        } else if ((addr >= KERNEL_START_ADDR && addr < (uintptr_t) end)
                   || addr == KERNEL_STACK_TOP - PAGESIZE) {
            owner = PO_KERNEL;
        } else {
            owner = PO_FREE;
        }

        // ADDED: kernel owns this, prevent application code from accessing
        // note: not the console
        if (addr < PROC_START_ADDR && addr != (uintptr_t) console) {
            virtual_memory_map(kernel_pagetable, addr, addr, PAGESIZE, (PTE_P|PTE_W), NULL);
        }
        pageinfo[PAGENUMBER(addr)].owner = owner;
        pageinfo[PAGENUMBER(addr)].refcount = (owner != PO_FREE);
    }
}


// check_page_table_mappings
//    Check operating system invariants about kernel mappings for page
//    table `pt`. Panic if any of the invariants are false.

void check_page_table_mappings(x86_64_pagetable* pt) {
    extern char start_data[], end[];
    assert(PTE_ADDR(pt) == (uintptr_t) pt);

    // kernel memory is identity mapped; data is writable
    for (uintptr_t va = KERNEL_START_ADDR; va < (uintptr_t) end;
         va += PAGESIZE) {
        vamapping vam = virtual_memory_lookup(pt, va);
        if (vam.pa != va) {
            console_printf(CPOS(22, 0), 0xC000, "%p vs %p\n", va, vam.pa);
        }
        assert(vam.pa == va);
        if (va >= (uintptr_t) start_data) {
            assert(vam.perm & PTE_W);
        }
    }

    // kernel stack is identity mapped and writable
    uintptr_t kstack = KERNEL_STACK_TOP - PAGESIZE;
    vamapping vam = virtual_memory_lookup(pt, kstack);
    assert(vam.pa == kstack);
    assert(vam.perm & PTE_W);
}


// check_page_table_ownership
//    Check operating system invariants about ownership and reference
//    counts for page table `pt`. Panic if any of the invariants are false.

static void check_page_table_ownership_level(x86_64_pagetable* pt, int level,
                                             int owner, int refcount);

void check_page_table_ownership(x86_64_pagetable* pt, pid_t pid) {
    // calculate expected reference count for page tables
    int owner = pid;
    int expected_refcount = 1;
    if (pt == kernel_pagetable) {
        owner = PO_KERNEL;
        for (int xpid = 0; xpid < NPROC; ++xpid) {
            if (processes[xpid].p_state != P_FREE
                && processes[xpid].p_pagetable == kernel_pagetable) {
                ++expected_refcount;
            }
        }
    }
    check_page_table_ownership_level(pt, 0, owner, expected_refcount);
}

static void check_page_table_ownership_level(x86_64_pagetable* pt, int level,
                                             int owner, int refcount) {
    assert(PAGENUMBER(pt) < NPAGES);
    assert(pageinfo[PAGENUMBER(pt)].owner == owner);
    assert(pageinfo[PAGENUMBER(pt)].refcount == refcount);
    if (level < 3) {
        for (int index = 0; index < NPAGETABLEENTRIES; ++index) {
            if (pt->entry[index]) {
                x86_64_pagetable* nextpt =
                    (x86_64_pagetable*) PTE_ADDR(pt->entry[index]);
                check_page_table_ownership_level(nextpt, level + 1, owner, 1);
            }
        }
    }
}


// check_virtual_memory
//    Check operating system invariants about virtual memory. Panic if any
//    of the invariants are false.

void check_virtual_memory(void) {
    // Process 0 must never be used.
    assert(processes[0].p_state == P_FREE);

    // The kernel page table should be owned by the kernel;
    // its reference count should equal 1, plus the number of processes
    // that don't have their own page tables.
    // Active processes have their own page tables. A process page table
    // should be owned by that process and have reference count 1.
    // All level-2-4 page tables must have reference count 1.

    check_page_table_mappings(kernel_pagetable);
    check_page_table_ownership(kernel_pagetable, -1);

    for (int pid = 0; pid < NPROC; ++pid) {
        if (processes[pid].p_state != P_FREE
            && processes[pid].p_pagetable != kernel_pagetable) {
            check_page_table_mappings(processes[pid].p_pagetable);
            check_page_table_ownership(processes[pid].p_pagetable, pid);
        }
    }

    // Check that all referenced pages refer to active processes
    for (int pn = 0; pn < PAGENUMBER(MEMSIZE_PHYSICAL); ++pn) {
        if (pageinfo[pn].refcount > 0 && pageinfo[pn].owner >= 0) {
            assert(processes[pageinfo[pn].owner].p_state != P_FREE);
        }
    }
}


// memshow_physical
//    Draw a picture of physical memory on the CGA console.

static const uint16_t memstate_colors[] = {
    'K' | 0x0D00, 'R' | 0x0700, '.' | 0x0700, '1' | 0x0C00,
    '2' | 0x0A00, '3' | 0x0900, '4' | 0x0E00, '5' | 0x0F00,
    '6' | 0x0C00, '7' | 0x0A00, '8' | 0x0900, '9' | 0x0E00,
    'A' | 0x0F00, 'B' | 0x0C00, 'C' | 0x0A00, 'D' | 0x0900,
    'E' | 0x0E00, 'F' | 0x0F00
};

void memshow_physical(void) {
    console_printf(CPOS(0, 32), 0x0F00, "PHYSICAL MEMORY");
    for (int pn = 0; pn < PAGENUMBER(MEMSIZE_PHYSICAL); ++pn) {
        if (pn % 64 == 0) {
            console_printf(CPOS(1 + pn / 64, 3), 0x0F00, "0x%06X ", pn << 12);
        }

        int owner = pageinfo[pn].owner;
        if (pageinfo[pn].refcount == 0) {
            owner = PO_FREE;
        }
        uint16_t color = memstate_colors[owner - PO_KERNEL];
        // darker color for shared pages
        if (pageinfo[pn].refcount > 1) {
            color &= 0x77FF;
        }

        console[CPOS(1 + pn / 64, 12 + pn % 64)] = color;
    }
}


// memshow_virtual(pagetable, name)
//    Draw a picture of the virtual memory map `pagetable` (named `name`) on
//    the CGA console.

void memshow_virtual(x86_64_pagetable* pagetable, const char* name) {
    assert((uintptr_t) pagetable == PTE_ADDR(pagetable));

    console_printf(CPOS(10, 26), 0x0F00, "VIRTUAL ADDRESS SPACE FOR %s", name);
    for (uintptr_t va = 0; va < MEMSIZE_VIRTUAL; va += PAGESIZE) {
        vamapping vam = virtual_memory_lookup(pagetable, va);
        uint16_t color;
        if (vam.pn < 0) {
            color = ' ';
        } else {
            assert(vam.pa < MEMSIZE_PHYSICAL);
            int owner = pageinfo[vam.pn].owner;
            if (pageinfo[vam.pn].refcount == 0) {
                owner = PO_FREE;
            }
            color = memstate_colors[owner - PO_KERNEL];
            // reverse video for user-accessible pages
            if (vam.perm & PTE_U) {
                color = ((color & 0x0F00) << 4) | ((color & 0xF000) >> 4)
                    | (color & 0x00FF);
            }
            // darker color for shared pages
            if (pageinfo[vam.pn].refcount > 1) {
                color &= 0x77FF;
            }
        }
        uint32_t pn = PAGENUMBER(va);
        if (pn % 64 == 0) {
            console_printf(CPOS(11 + pn / 64, 3), 0x0F00, "0x%06X ", va);
        }
        console[CPOS(11 + pn / 64, 12 + pn % 64)] = color;
    }
}


// memshow_virtual_animate
//    Draw a picture of process virtual memory maps on the CGA console.
//    Starts with process 1, then switches to a new process every 0.25 sec.

void memshow_virtual_animate(void) {
    static unsigned last_ticks = 0;
    static int showing = 1;

    // switch to a new process every 0.25 sec
    if (last_ticks == 0 || ticks - last_ticks >= HZ / 2) {
        last_ticks = ticks;
        ++showing;
    }

    // the current process may have died -- don't display it if so
    while (showing <= 2*NPROC
           && processes[showing % NPROC].p_state == P_FREE) {
        ++showing;
    }
    showing = showing % NPROC;

    if (processes[showing].p_state != P_FREE) {
        char s[4];
        snprintf(s, 4, "%d ", showing);
        memshow_virtual(processes[showing].p_pagetable, s);
    }
}
