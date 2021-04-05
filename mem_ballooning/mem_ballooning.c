#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/sched/signal.h>
#include <linux/swap.h> // For vm_swappiness

#define SIG_BALLOON (SIGRTMAX-1)

#define DEBUG 1

#if defined(DEBUG) && DEBUG > 0
    #define DEBUG_PRINT(fmt, args...) printk("DEBUG: %s:%d:%s(): " fmt, \
        __FILE__, __LINE__, __func__, ##args)
#else
    #define DEBUG_PRINT(fmt, args...) /* Don't do anything when DEBUG is off or absent */
#endif


struct mb_n_reg_node_t
{
    pid_t pid;
    struct mb_n_reg_node_t *next;
};

struct mb_n_reg_node_t* mb_n_reg_node_head = NULL;
struct mb_n_reg_node_t* mb_n_reg_node_tail = NULL;


static struct task_struct *cur_task = NULL;

void mb_disable_anon_page_swap(void);



asmlinkage long __x64_sys_init_ballooning(void){
    struct kernel_siginfo info;
    int ret;
    pid_t proc_pid;

    DEBUG_PRINT("init_ballooning syscall has been called\n");
    DEBUG_PRINT("PID of calling process is : %d\n", current->pid);

    /* current is a macro defined in arch/x86/include/asm/current.h
        expands to a function returning pointer (task_struct) to the current process
        tgid denotes thread group id
    */

    /* Assuming non-premptive kernel. Will have to use lock otherwise. */
    
    cur_task = get_current();

    DEBUG_PRINT("Added the calling process to registered process list for ballooning\n");


    DEBUG_PRINT("Sending a test signal to the process\n");
    

    memset(&info, 0, sizeof(struct kernel_siginfo));
    info.si_signo = SIG_BALLOON;
    info.si_code = SI_KERNEL;
    info.si_int = 1234;

    /*
        Tip : send_sig_info moved to linux/sched/signal.h since 4.11 
        and 4.20 has changed siginfo to kernel_siginfo
    */

    /* send the signal */
    ret = send_sig_info(SIG_BALLOON, &info, cur_task);    

    if (ret < 0) {
		DEBUG_PRINT("error sending SIGBALLOON signal\n");
		return ret;
	}

    mb_disable_anon_page_swap();

    return 0;
}


// To disable the default kernel swapping algorithm
// so that no anonymous page is swapped after ballooning driver
// is initialized
void mb_disable_anon_page_swap(void){
    DEBUG_PRINT("Attempting to change vm_swappiness to 0");
    vm_swappiness = 0; // To Do : Check if a mutex is needed here
    DEBUG_PRINT("vm_swappiness changed to 0");
}

