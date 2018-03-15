#define M61_DISABLE 1
#include "m61.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <inttypes.h>
#include <assert.h>

/*can I include this for INT_MAX ?*/
#include <limits.h>
/*can I include this for seeding purposes?*/
#include <time.h>

/*set a constant for the boundary value (w cause my name is will)*/
#define BOUNDARY_VALUE 'w'
#define TRUE 't'
#define FALSE 'f'


// metadata to attach to allocations for record keeping
// our metadata is a doubly linked list that also maintains important information
// about each allocation such as size, boundary value, whether or not the 
// allocation is active, where it originated, and where it was stored in memory
// we keep track of the item added last to the doubly linked list
typedef struct metadata_block {
    int sz; // size of the users allocation
    char boundary_value; // first value outside of the users allocation
    char is_active; // indicates an allocated block of memory is not yet freed
    struct metadata_block *prev_metadata; // pointer backwards in doubly linked list
    struct metadata_block *next_metadata; // pointer forwards in doubly linked list
    const char* leak_report_file_ptr; // file of allocation
    int leak_report_line; // line number of allocation
    void* memory_location; // where in memory the allocation was originally assigned
} metadata_block;

// track last metadata in doubly linked list
metadata_block* last_metadata = NULL;

// global information about mallocs, frees, allocation size, etc.
int malloc_count = 0; // number of mallocs
int free_count = 0; // number of frees
unsigned long total_allocated_memory = 0; // total allocated memory
int currently_allocated_memory = 0; // currently allocated memory
int fail_count = 0; // number of failed allocations
int fail_size = 0; // size of failed allocations
void* heap_min; // min address size
void* heap_max; // max address size

// data for our heavy hitter report
// our data for heavy hitter calculations if a singly linked list that
// contains information about allocations from a unique file/line combination
// the data tracked includes this file/line combo, the number of allocations
// made from that place, and the total bytes allocated there
// we keep track of the head of this linked list, as well as a global that
// stores the total allocation size for the heavy hitter report
typedef struct heavy_hitter {
    const char* file; // file name
    int line; // line number
    int num_allocations; // number of allocations
    int total_allocation_sz; // total allocation size
    struct heavy_hitter* next_hh; // next heavy_hitter
} heavy_hitter;

// pointer to first heavy hitter in linked list
heavy_hitter* first_hh = NULL;

// heavy hitter total allocation size
unsigned long hh_total_allocated_memory = 0;
// heavy hitter total number of allocations
unsigned long hh_total_num_allocations = 0;



/// m61_malloc(sz, file, line)
///    Return a pointer to `sz` bytes of newly-allocated dynamic memory.
///    The memory is not initialized. If `sz == 0`, then m61_malloc may
///    either return NULL or a unique, newly-allocated pointer value.
///    The allocation request was at location `file`:`line`.

void* m61_malloc(size_t sz, const char* file, int line) {
    (void) file, (void) line;   // avoid uninitialized variable warnings
    // Your code here.
    
    // don't allocated more than INT_MAX
    if (sz > INT_MAX) {
        fail_count += 1;
        fail_size += sz;
        return NULL;
    }

    // add space for metadata and + 16 for detecting overlap
    // note: added 16 bytes to the end so that for the overwrite tests,
    // we don't hit protected memory which the OS will abort on
    metadata_block *metadata_ptr = base_malloc(sz + sizeof(metadata_block) + 16);

    // check for failed allocation
    if (!metadata_ptr) {
        fail_count += 1;
        fail_size += sz;
        return NULL;
    } else {
        // increment malloc
        malloc_count += 1;

        // increment total and currently allocated memory
        total_allocated_memory += sz;
        currently_allocated_memory += sz;

        // fill our metadata
        metadata_ptr->sz = sz;
        metadata_ptr->is_active = TRUE;
        metadata_ptr->leak_report_file_ptr = file;
        metadata_ptr->leak_report_line = line;
        metadata_ptr->next_metadata = NULL;

        // chain metadata backwards if there is a previous value
        if (last_metadata != NULL) {
            metadata_ptr->prev_metadata = last_metadata;
            last_metadata->next_metadata = metadata_ptr;
        } else {
            // otherwise make our prev_metadata pointer null
            metadata_ptr->prev_metadata = NULL;
        }

        // set last_metadata
        last_metadata = metadata_ptr;

        // get payload pointer, this increments one metadata_block worth of 
        // space because this is a metadata_block pointer
        void* payload_ptr = metadata_ptr + 1;

        // pointer to boundary value
        char* boundary_ptr = payload_ptr + sz;

        // set boundary_value and assign to our metadata block
        *boundary_ptr = BOUNDARY_VALUE;
        metadata_ptr->boundary_value = *boundary_ptr;

        // also track our memory location at time of allocation
        metadata_ptr->memory_location = metadata_ptr;

        // update heap_min/heap_max
        if (!heap_min || payload_ptr < heap_min) {
            heap_min = payload_ptr;
        }

        // set to end of allocation
        if (payload_ptr + sz > heap_max) {
            heap_max = payload_ptr + sz;
        }

        // perform heavy hitter calculations
        // seed our random number generator with time and number of mallocs
        srand48(time(NULL) + malloc_count);
        // sampling
        double should_count = drand48();
        // if it's under sampling threshhold of 0.01, update heavy hitter data
        if (should_count <= 0.01) {
            // increment the number of allocations
            hh_total_num_allocations += 1;
            // search through our heavy_hitter list to find if this file and 
            // line has already made an allocation
            heavy_hitter* tmp_hh = first_hh; // get pointer to first_hh
            char already_exists = FALSE; // set up a flag
            // move through linked list
            while (tmp_hh) {
                if (tmp_hh->file == file && tmp_hh->line == line) {
                    // we already have this file and line, so increment
                    // the count and size
                    tmp_hh->num_allocations += 1; // the count
                    tmp_hh->total_allocation_sz += sz ; // the size
                    hh_total_allocated_memory += sz ; // total size count
                    already_exists = TRUE; // notify with the flag
                    break; // break out of the while loop
                }
                // reassign the temp_hh
                tmp_hh = tmp_hh->next_hh;
            }
            // if we haven't yet made an allocation, we make a new
            // allocation for this file and line
            if (already_exists == FALSE) {
                heavy_hitter* new_hh = malloc(sizeof(heavy_hitter)); // allocate space for hh
                new_hh->file = file; // assign file
                new_hh->line = line; // assign line
                new_hh->num_allocations = 1; // assign 1 allocation
                new_hh->total_allocation_sz = sz; // assign size
                hh_total_allocated_memory += sz ; // total size count
                // if this is the first hh, it gets a null next_hh
                if (!first_hh) {
                    new_hh->next_hh = NULL; // last hh in the chain, no next
                } else {
                    new_hh->next_hh = first_hh; // point it at the first_hh in the chain
                }

                first_hh = new_hh; // reassign the first_hh to this one
            }
        }

        // return pointer to payload
        return payload_ptr;
        /*return base_malloc(sz);*/
    }
}


/// m61_validate(ptr, file, line)
///    Ensure the pointer we are working with is valid.

void m61_validate(void *ptr, const char *file, int line) {
    // validate pointers before doing anything with them

    // access metadata for this ptr
    metadata_block *metadata_ptr = ptr - sizeof(metadata_block);

    // abort if this is an invalid pointer or not in the heap by checking:
    //      alignment
    //      min/max bounds
    //      active status
    //      memory location at time of allocation
    if ((long) metadata_ptr % 8 != 0 || ptr < heap_min || ptr > heap_max || metadata_ptr->is_active != TRUE || metadata_ptr->memory_location != metadata_ptr) {
        // if we are within the heap min/max, then this just isn't an 
        // allocated pointer, otherwise it's not in the heap at all
        if (ptr > heap_min && ptr < heap_max) {
            printf("MEMORY BUG: %s:%d: invalid free of pointer %p, not allocated\n", file, line, ptr);
            // check if this is inside another memory block
            // establish tmp pointer
            metadata_block* tmp_last_metadata = last_metadata;
            // move through our current allocations
            while (tmp_last_metadata) {
                // pointer to payload
                void* payload_ptr = tmp_last_metadata + 1; 
                // pointer to the boundary
                void* boundary_ptr = payload_ptr + tmp_last_metadata->sz;
                // see if this pointer is inside of this range
                if (ptr > (void *) tmp_last_metadata && ptr < boundary_ptr) {
                    printf("  %s:%d: %p is %lu bytes inside a %d byte region allocated here\n", tmp_last_metadata->leak_report_file_ptr, tmp_last_metadata->leak_report_line, ptr, ptr-payload_ptr, tmp_last_metadata->sz);
                    break;
                }
                // update tmp pointer
                tmp_last_metadata = tmp_last_metadata->prev_metadata;
            }
        } else {
            printf("MEMORY BUG %s:%d: invalid free of pointer %p, not in heap\n", file, line, ptr);
        }
        abort();
    }

    // abort if this pointer is not consitent with the ones before it in doubly linked list
    if (metadata_ptr->prev_metadata && metadata_ptr->prev_metadata->next_metadata != metadata_ptr) {
        printf("MEMORY BUG %s:%d: invalid free of pointer %p\n", file, line, ptr);
        abort();
    }

    // abort if this pointer is not consitent with the ones after it in doubly linked list
    if (metadata_ptr->next_metadata && metadata_ptr->next_metadata->prev_metadata != metadata_ptr) {
        printf("MEMORY BUG %s:%d: invalid free of pointer %p\n", file, line, ptr);
        abort();
    }

    // get boundary ptr
    char* boundary_ptr = ptr + metadata_ptr->sz;

    // abort if there has been an invalid write outside the allocated space (by checking boundary)
    if (metadata_ptr->boundary_value != *boundary_ptr) {
        printf("MEMORY BUG %s:%d: detected wild write during free of pointer %p\n", file, line, ptr);
        abort();
    }

    return;
}


/// m61_free(ptr, file, line)
///    Free the memory space pointed to by `ptr`, which must have been
///    returned by a previous call to m61_malloc and friends. If
///    `ptr == NULL`, does nothing. The free was called at location
///    `file`:`line`.

void m61_free(void *ptr, const char *file, int line) {
    /*(void) file, (void) line;   // avoid uninitialized variable warnings*/
    // Your code here.
    
    // can free a NULL ptr, nothing should happen
    if (ptr == NULL) {
        return;
    }

    // make sure this is a valid pointer
    m61_validate(ptr, file, line);

    // access metadata for this ptr
    metadata_block *metadata_ptr = ptr - sizeof(metadata_block);

    // increment free
    free_count += 1;

    // decrement currently allocated_memory
    currently_allocated_memory -= metadata_ptr->sz;

    // update metadata block to indicate it's no longer active
    metadata_ptr->is_active = FALSE;

    // prior to freeing everything, update our last/next pointers
    // if this is the last pointer, simply move the last pointer one step down the doubly linked list
    if (last_metadata == metadata_ptr) {
        last_metadata = metadata_ptr->prev_metadata;
        // update the prev_metadata if it exists
        if (metadata_ptr->prev_metadata) {
            metadata_ptr->prev_metadata->next_metadata = NULL;
        }
    } else if (!(metadata_ptr->prev_metadata)) { // case where this is the first link in the chain
        // update the next_metadata if it exists
        if (metadata_ptr->next_metadata) {
            metadata_ptr->next_metadata->prev_metadata = NULL; // reassign next one's prev pointer to null
        }
    } else { // otherwise this is in the middle and we need to reassign both
        metadata_ptr->next_metadata->prev_metadata = metadata_ptr->prev_metadata; // reassign next one's prev pointer
        metadata_ptr->prev_metadata->next_metadata = metadata_ptr->next_metadata; // reassign previous one's next pointer
    }

    // free the entire block
    base_free(metadata_ptr);
    /*base_free(ptr);*/
}


/// m61_realloc(ptr, sz, file, line)
///    Reallocate the dynamic memory pointed to by `ptr` to hold at least
///    `sz` bytes, returning a pointer to the new block. If `ptr` is NULL,
///    behaves like `m61_malloc(sz, file, line)`. If `sz` is 0, behaves
///    like `m61_free(ptr, file, line)`. The allocation request was at
///    location `file`:`line`.

void* m61_realloc(void* ptr, size_t sz, const char* file, int line) {
    /*void* new_ptr = NULL;*/
    /*if (sz) {*/
        /*new_ptr = m61_malloc(sz, file, line);*/
    /*}*/
    /*if (ptr && new_ptr) {*/
        /*// Copy the data from `ptr` into `new_ptr`.*/
        /*// To do that, we must figure out the size of allocation `ptr`.*/
        /*// Your code here (to fix test014).*/
    /*}*/
    /*m61_free(ptr, file, line);*/
    /*return new_ptr;*/

    // initialize new_ptr
    void* new_ptr = NULL;
    // if we have sz, allocate for new_ptr
    if (sz) {
        new_ptr = m61_malloc(sz, file, line);
    }
    // if we have both an original and new pointer, go about reallocating
    if (ptr && new_ptr) {
        // Copy the data from `ptr` into `new_ptr`.
        // To do that, we must figure out the size of allocation `ptr`.
        // Your code here (to fix test014).

        // make sure this is a valid pointer
        m61_validate(ptr, file, line);

        // get pointer to original metadata
        metadata_block* metadata_ptr = ptr - sizeof(metadata_block);

        // get pointer to new metadata
        metadata_block* new_metadata_ptr = new_ptr - sizeof(metadata_block);

        // reassign the last metadata if necessary
        if (last_metadata == metadata_ptr) {
            last_metadata = new_metadata_ptr;
        }

        // access the old size of the allocation
        size_t old_sz = metadata_ptr->sz;

        // reallocate based on which allocation size is smaller
        if (old_sz < sz) {
            // if old_sz is smaller, memcopy that much info
            memcpy(new_ptr, ptr, old_sz);
            // adjust the size
            new_metadata_ptr->sz = old_sz;
            // adjust the currently_allocated_memory in this case because
            // we allocated for everything in sz but didn't end up using
            // it all as it's greater than old_sz
            currently_allocated_memory -= (sz - old_sz);
        } else {
            // otherwise, memcopy the new sz, which is smaller
            memcpy(new_ptr, ptr, sz);
        }

        // free the old pointer
        m61_free(ptr, file, line);

        // update our metadata block
        new_metadata_ptr->is_active = TRUE;
        new_metadata_ptr->leak_report_file_ptr = metadata_ptr->leak_report_file_ptr;
        new_metadata_ptr->leak_report_line = metadata_ptr->leak_report_line;
        new_metadata_ptr->prev_metadata = metadata_ptr->prev_metadata;
        new_metadata_ptr->next_metadata = metadata_ptr->next_metadata;

        // reassign the pointers around new_metadata_ptr in the doubly linked list if they exist
        if (metadata_ptr->next_metadata) {
            metadata_ptr->next_metadata->prev_metadata = new_metadata_ptr;
        }
        if (metadata_ptr->prev_metadata) {
            metadata_ptr->prev_metadata->next_metadata = new_metadata_ptr;
        }

        // set boundary value, which has been overwritten
        new_metadata_ptr->boundary_value = metadata_ptr->boundary_value;
        *(char*) (new_ptr + new_metadata_ptr->sz) = metadata_ptr->boundary_value;

        // set memory location
        new_metadata_ptr->memory_location = new_metadata_ptr;

        // done
        return new_ptr;
    }

    if (!ptr) {
        // if we get here, it's because we didn't have a ptr and should be 
        // returning the result of malloc - no need to free in this case
        return new_ptr;
    }

    // if we get here, it's because we didn't have sz (and thus are freeing
    // the original pointer)

    // free
    m61_free(ptr, file, line);

    // done
    return new_ptr;
}


/// m61_calloc(nmemb, sz, file, line)
///    Return a pointer to newly-allocated dynamic memory big enough to
///    hold an array of `nmemb` elements of `sz` bytes each. The memory
///    is initialized to zero. If `sz == 0`, then m61_malloc may
///    either return NULL or a unique, newly-allocated pointer value.
///    The allocation request was at location `file`:`line`.

void* m61_calloc(size_t nmemb, size_t sz, const char* file, int line) {
    // Your code here (to fix test016).
    /*void* ptr = m61_malloc(nmemb * sz, file, line);*/
    /*if (ptr) {*/
        /*memset(ptr, 0, nmemb * sz);*/
    /*}*/
    /*return ptr;*/
    // don't overflow with the number of slots
    if (nmemb > INT_MAX) {
        fail_count += 1;
        fail_size += nmemb * sz;
        return NULL;
    }
    // allocate
    void* ptr = m61_malloc(nmemb * sz, file, line);
    // set to 0
    if (ptr) {
        memset(ptr, 0, nmemb * sz);
    }
    return ptr;
}


/// m61_getstatistics(stats)
///    Store the current memory statistics in `*stats`.

void m61_getstatistics(struct m61_statistics* stats) {
    // Stub: set all statistics to enormous numbers
    /*memset(stats, 255, sizeof(struct m61_statistics));*/
    memset(stats, 0, sizeof(struct m61_statistics));
    // Your code here.

    // set all our stats from global values
    stats->ntotal = malloc_count; // total mallocs
    stats->nactive = malloc_count - free_count; // total active (mallocs - frees)
    stats->total_size = total_allocated_memory; // total active size
    stats->active_size = currently_allocated_memory; // currently active size
    stats->nfail = fail_count; // number of fails
    stats->fail_size = fail_size; // fail size
    stats->heap_min = heap_min; // heap_min
    stats->heap_max = heap_max; // heap_max
}


/// m61_printstatistics()
///    Print the current memory statistics.

void m61_printstatistics(void) {
    struct m61_statistics stats;
    m61_getstatistics(&stats);

    printf("malloc count: active %10llu   total %10llu   fail %10llu\n",
           stats.nactive, stats.ntotal, stats.nfail);
    printf("malloc size:  active %10llu   total %10llu   fail %10llu\n",
           stats.active_size, stats.total_size, stats.fail_size);
}


/// m61_printleakreport()
///    Print a report of all currently-active allocated blocks of dynamic
///    memory.

void m61_printleakreport(void) {
    // Your code here.
    // start at the end of the doubly linked list
    metadata_block* tmp_metadata = last_metadata;
    while (tmp_metadata) {
        printf("LEAK CHECK: %s:%d: allocated object %p with size %d\n", tmp_metadata->leak_report_file_ptr, tmp_metadata->leak_report_line, tmp_metadata + 1, tmp_metadata->sz);
        // move through list
        tmp_metadata = tmp_metadata->prev_metadata;
    }
}

// m61_printheavyhitterreport()
//     print a report of the parts of a program allocating the most memory

void m61_printheavyhitterreport() {
    int most_allocations = 0; // keep track of the location with the most allocations
    const char* most_allocations_file_name; // the file
    int most_allocations_line_number; // the line number

    // first in heavy_hitter chain
    heavy_hitter* tmp_hh = first_hh;
    while (tmp_hh) {
        // filter for things contributing to more than 10% of allocation size
        if (tmp_hh->total_allocation_sz / (float) hh_total_allocated_memory >= 0.1) {
            printf("Heavy Hitter => location: %s:%d | allocation size: %d bytes | allocation percent: %.2f%% | number of allocations: %d\n", tmp_hh->file, tmp_hh->line, tmp_hh->total_allocation_sz, (float) 100 * tmp_hh->total_allocation_sz / (float) hh_total_allocated_memory, tmp_hh->num_allocations);
        }
        // filter for things contributing to more than 10% of allocations
        if (tmp_hh->num_allocations / (float) hh_total_num_allocations >= 0.1) {
            printf("Heavy Allocator => location: %s:%d | number of allocations: %d\n", tmp_hh->file, tmp_hh->line, tmp_hh->num_allocations);
        }
        // update most allocations if necessary
        if (tmp_hh->num_allocations > most_allocations) {
            most_allocations = tmp_hh->num_allocations;
            most_allocations_file_name = tmp_hh->file;
            most_allocations_line_number = tmp_hh->line;
        }
        // move to next heavy_hitter
        tmp_hh = tmp_hh->next_hh;
    }
    // if we have any allocations
    if (most_allocations > 0) {
        printf("Most Allocations => location: %s:%d | number of allocations: %d\n", most_allocations_file_name, most_allocations_line_number, most_allocations);
    }
}
