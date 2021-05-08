#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/sched/signal.h>
#include <linux/swap.h> 

#include <linux/mm.h>
#include <linux/mman.h>

#include <linux/syscalls.h>
#include <linux/mmzone.h>



/*
 * Author : Shashank Singh (shashanksing@iisc.ac.in, cse.shashanksingh@gmail.com)
 * Contains the definition for a system call init_ballooning for 64 bit linux kernel.
 */

#define SIG_BALLOON (SIGRTMAX-1)
#define PAGE_SIZE_BYTES (4096)

#define DEBUG 1
#if defined(DEBUG) && DEBUG > 0
    #define DEBUG_PRINT(fmt, args...) printk("KDEBUG: %s:%d:%s(): " fmt, \
        __FILE__, __LINE__, __func__, ##args)
#else
    #define DEBUG_PRINT(fmt, args...) /* Don't do anything when DEBUG is off or absent */
#endif


/*
 * Flag that denotes whether memory ballooning some process has
 * registered for memory ballooning. This flag is used to send 
 * SIGBALLOON to the process as well as disabling anon page 
 * swapping in vm_scan.c
 */
int mem_balloon_is_active=0;



/*
 * Flag that denotes whether a signal should be sent to process
 * when free phy mem falls below threshold. Used to implement 
 * the wait time of 10 seconds before sending another signal.
 */
int mem_balloon_should_send_signal=1;

/*
 * The pid of the process currently registered for memory
 * ballooning. Used to send the SIGBALLOON signal to the process.
 */
pid_t mem_balloon_reg_task_pid;


/* 
 * To disable the default kernel swapping algorithm so that
 * no anonymous page is swapped after ballooning driver is
 * initialized.
 */ 
void mb_disable_anon_page_swap(void){
    /*
     * Following approaches were explored to disable swapping of anon pages
     *  - Pinning of process pages in RAM 
     *  - Bypassing the swapping mechanism in shrink_page_list
     *  - Changing the scan balance of get_scan_count - This by far seems to be 
     *    the best one, considering it has a very clean code change and just instructs
     *    that no anon page must be swapped. So, kernel won't even try to loop
     *    through anon pages.
     *
     * The vm_swappiness param is not as important as of now, as we are directly 
     * checking in vm_scan.c that if memory ballooning is enabled, set the scan_balance
     * to SCAN_FILE.
     */

    DEBUG_PRINT("Trying to change vm_swappinees to disable swapping\n");
    // vm_swappiness = 0; // To Do : Check if a mutex is needed here
    // DEBUG_PRINT("vm_swappiness changed to 0\n");
}



/* 
 * Implementation of register ballooning system call.
 */
SYSCALL_DEFINE0(init_ballooning){
    DEBUG_PRINT("init_ballooning syscall has been called\n");
    DEBUG_PRINT("PID of calling process is : %d\n", current->pid);

    /* 
     * Save the current process to send the SIGBALLOON signal when needed
     * Also, mark the mem_balloon_is_active flag to enable the check
     * for physical memory.
     *
     * Note to self : current is a macro defined in arch/x86/include/asm/current.h
     * and expands to a function returning pointer (task_struct) to the 
     * current process
    */  

    mem_balloon_reg_task_pid = current->pid;
    mem_balloon_is_active = 1;

    DEBUG_PRINT("Saved the current process identity for sending ballooning signal later\n");
    
    mb_disable_anon_page_swap();

    return 0;
}


/* 
 * Implementation of mb_suggest_swap system call.
 * Will be used by userspace application to suggest pages to swap
 * Input : an array of start VAs of pages to swap out, size of the array
 */

 /*
  * The PA vs VA dilemma : There are two options when suggesting pages to swap out 
  * 1. Suggesting physical page frames, 2. Suggesting virtual page numbers
  * The first is a breach of security as no door should be opened to userspace to 
  * manipulate physical pages directly as they don't respect process isolation and 
  * concern boundaries. So, I went ahead with virtual pages although there's a slight
  * performance impact due to the page walk involved before swapping.  
 */
SYSCALL_DEFINE2(mb_suggest_swap, unsigned long* __user, virt_pg_list_start, unsigned, list_size){
    unsigned i;
    struct mm_struct *cur_mm =  current->mm;
    unsigned long va_pg_start;

    unsigned long *virt_pg_list_kernel;
    unsigned long n_bytes_uncopied;

    int ret_val_madvise;

    DEBUG_PRINT("mb_suggest_swap syscall has been called with list start : %px, %lx\n", virt_pg_list_start, (unsigned long)virt_pg_list_start);
    DEBUG_PRINT("list size : %d\n", list_size);

    virt_pg_list_kernel = kmalloc(sizeof(unsigned long)*list_size,GFP_KERNEL);

    n_bytes_uncopied = copy_from_user(virt_pg_list_kernel, virt_pg_list_start, sizeof(unsigned long)*list_size);

    if(n_bytes_uncopied) {
        DEBUG_PRINT("copy_to_user couldn't copy %lu bytes\n", n_bytes_uncopied);
    }

    for(i=0; i<list_size; ++i) {
        va_pg_start = *(virt_pg_list_kernel+i);
        // DEBUG_PRINT("Trying to swap out page : %lx\n", va_pg_start);
        ret_val_madvise = do_madvise(cur_mm, va_pg_start, PAGE_SIZE_BYTES, MADV_PAGEOUT);
        if(ret_val_madvise) {
            DEBUG_PRINT("------ERROR : do_madvise returned non zero value--------\n");
        }

        
    }

    kfree(virt_pg_list_kernel);

    

    return 0;
}

