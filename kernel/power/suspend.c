/*
 * kernel/power/suspend.c - Suspend to RAM and standby functionality.
 *
 * Copyright (c) 2003 Patrick Mochel
 * Copyright (c) 2003 Open Source Development Lab
 * Copyright (c) 2009 Rafael J. Wysocki <rjw@sisk.pl>, Novell Inc.
 *
 * This file is released under the GPLv2.
 */

#include <linux/string.h>
#include <linux/delay.h>
#include <linux/errno.h>
#include <linux/init.h>
#include <linux/console.h>
#include <linux/cpu.h>
#include <linux/syscalls.h>
#include <linux/gfp.h>
#include <linux/io.h>
#include <linux/kernel.h>
#include <linux/list.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/export.h>
#include <linux/suspend.h>
#include <linux/syscore_ops.h>
#include <linux/rtc.h>
#include <trace/events/power.h>

#include "power.h"

#include <linux/mem_encrypt.h>
#include <linux/time.h>
#include <linux/kthread.h>

DEFINE_SPINLOCK(suspend_notify_lock);
DECLARE_COMPLETION(suspend_complete);
static int suspend_notify_req_pending = 0;

DEFINE_SPINLOCK(enable_encryption_lock);
/* Encryption is disabled by default.
 */
static int encryption_enabled = 0;

void req_suspend_notification(void) 
{
    unsigned long flags;
    printk("%s:%i, HELLO suspend_notify_req_pending == %i\n", __func__, __LINE__, suspend_notify_req_pending);

    spin_lock_irqsave(&suspend_notify_lock, flags);

    /* Only one process should be able to get a notification.
     */
    BUG_ON(suspend_notify_req_pending);

    suspend_notify_req_pending = 1;
    spin_unlock_irqrestore(&suspend_notify_lock, flags);
}
EXPORT_SYMBOL_GPL(req_suspend_notification);

void wait_for_suspend(void) 
{
    unsigned long flags;
    printk("%s:%i, suspend_complete.done == %u, suspend_notify_req_pending == %i\n", __func__, __LINE__, suspend_complete.done, suspend_notify_req_pending);

    spin_lock_irqsave(&suspend_notify_lock, flags);
    /* Process firsts needs to request to be notified.
     */
    BUG_ON(!suspend_notify_req_pending);
    spin_unlock_irqrestore(&suspend_notify_lock, flags);

    wait_for_completion(&suspend_complete);
    INIT_COMPLETION(suspend_complete);
    spin_lock_irqsave(&suspend_notify_lock, flags);
    suspend_notify_req_pending = 0;
    spin_unlock_irqrestore(&suspend_notify_lock, flags);
}
EXPORT_SYMBOL_GPL(wait_for_suspend);

void disable_encryption(void)
{
    unsigned long flags;
    printk("%s:%i, encryption_enabled == %i\n", __func__, __LINE__, encryption_enabled);

    /* It's ok it it's already disabled.
     */

    spin_lock_irqsave(&enable_encryption_lock, flags);
    encryption_enabled = 0;
    spin_unlock_irqrestore(&enable_encryption_lock, flags);
}
EXPORT_SYMBOL_GPL(disable_encryption);

void enable_encryption(void)
{
    unsigned long flags;
    printk("%s:%i, encryption_enabled == %i\n", __func__, __LINE__, encryption_enabled);

    spin_lock_irqsave(&enable_encryption_lock, flags);
    BUG_ON(encryption_enabled);
    encryption_enabled = 1;
    spin_unlock_irqrestore(&enable_encryption_lock, flags);
}
EXPORT_SYMBOL_GPL(enable_encryption);

int is_encryption_enabled(void)
{
    unsigned long flags;
    int retval;
    printk("%s:%i, encryption_enabled == %i\n", __func__, __LINE__, encryption_enabled);

    spin_lock_irqsave(&enable_encryption_lock, flags);
    retval = encryption_enabled;
    spin_unlock_irqrestore(&enable_encryption_lock, flags);
    return retval;
}

void notify_suspend(void) 
{
    unsigned long flags;
    printk("%s:%i, suspend_complete.done == %u, suspend_notify_req_pending == %i\n", __func__, __LINE__, suspend_complete.done, suspend_notify_req_pending);
    spin_lock_irqsave(&suspend_notify_lock, flags);
    if (suspend_notify_req_pending) {
        /* A process has requested to be notified that suspend has finished. Signal this to it by 
         * incrementing the semaphore so it either unblocks (or doesn't block in the first place).
         */
        complete(&suspend_complete);
    }
    spin_unlock_irqrestore(&suspend_notify_lock, flags);
}

const char *const pm_states[PM_SUSPEND_MAX] = {
	[PM_SUSPEND_STANDBY]	= "standby",
	[PM_SUSPEND_MEM]	= "mem",
};

static const struct platform_suspend_ops *suspend_ops;

/**
 * suspend_set_ops - Set the global suspend method table.
 * @ops: Suspend operations to use.
 */
void suspend_set_ops(const struct platform_suspend_ops *ops)
{
	lock_system_sleep();
	suspend_ops = ops;
	unlock_system_sleep();
}
EXPORT_SYMBOL_GPL(suspend_set_ops);

bool valid_state(suspend_state_t state)
{
	/*
	 * All states need lowlevel support and need to be valid to the lowlevel
	 * implementation, no valid callback implies that none are valid.
	 */
	return suspend_ops && suspend_ops->valid && suspend_ops->valid(state);
}

/**
 * suspend_valid_only_mem - Generic memory-only valid callback.
 *
 * Platform drivers that implement mem suspend only and only need to check for
 * that in their .valid() callback can use this instead of rolling their own
 * .valid() callback.
 */
int suspend_valid_only_mem(suspend_state_t state)
{
	return state == PM_SUSPEND_MEM;
}
EXPORT_SYMBOL_GPL(suspend_valid_only_mem);

static int suspend_test(int level)
{
#ifdef CONFIG_PM_DEBUG
	if (pm_test_level == level) {
		printk(KERN_INFO "suspend debug: Waiting for 5 seconds.\n");
		mdelay(5000);
		return 1;
	}
#endif /* !CONFIG_PM_DEBUG */
	return 0;
}

/**
 * suspend_prepare - Prepare for entering system sleep state.
 *
 * Common code run for every system sleep state that can be entered (except for
 * hibernation).  Run suspend notifiers, allocate the "suspend" console and
 * freeze processes.
 */
static int suspend_prepare(void)
{
	int error;

	if (!suspend_ops || !suspend_ops->enter)
		return -EPERM;

	pm_prepare_console();

	error = pm_notifier_call_chain(PM_SUSPEND_PREPARE);
	if (error)
		goto Finish;

	error = suspend_freeze_processes();
	if (!error)
		return 0;

	suspend_stats.failed_freeze++;
	dpm_save_failed_step(SUSPEND_FREEZE);
 Finish:
	pm_notifier_call_chain(PM_POST_SUSPEND);
	pm_restore_console();
	return error;
}

/* default implementation */
void __attribute__ ((weak)) arch_suspend_disable_irqs(void)
{
	local_irq_disable();
}

/* default implementation */
void __attribute__ ((weak)) arch_suspend_enable_irqs(void)
{
	local_irq_enable();
}

/* static int SUSPEND_BUSY_WAIT_SEC = 10; */
/* static int usec(struct timeval t) { */
/*     return (t.tv_sec*1e6) + t.tv_usec; */
/*     #<{(| return 0; |)}># */
/* } */

/* static void busy_wait(int duration) { */
/*  */
/*     #<{(| struct timeval start, cur; |)}># */
/*     unsigned long end = jiffies + (unsigned long) ((SUSPEND_BUSY_WAIT_SEC*1e3)/HZ); */
/*  */
/* 	BUG_ON(irqs_disabled()); */
/*     #<{(| unsigned long j1 = jiffies +  |)}># */
/*     #<{(| do_gettimeofday(&start); |)}># */
/*     printk("SUSPEND: start busy wait ...\n"); */
/*     do { */
/*         #<{(| do_gettimeofday(&cur); |)}># */
/*         cpu_relax(); */
/*     } while (time_before(jiffies, end)); */
/*     #<{(| } while (usec(cur) - usec(start) < SUSPEND_BUSY_WAIT_SEC*1e6); |)}># */
/*     #<{(| } while (1); |)}># */
/*     printk("SUSPEND: end busy wait after %i seconds.\n", SUSPEND_BUSY_WAIT_SEC); */
/*  */
/* } */

struct suspend_crypto_thread_args {
    struct completion suspend_crypto_thread_done;
    struct completion sensitive_processes_frozen;
    int return_code;
} _args;
void init_args(void) 
{
    init_completion(&_args.sensitive_processes_frozen);
    init_completion(&_args.suspend_crypto_thread_done);
    _args.return_code = 0;
}
struct task_struct * suspend_crypto_thread;
static int do_suspend_crypto_thread(void * data)
{
    struct suspend_crypto_thread_args * args = data;

    /* This thread is not frozen by the normal suspend path (in try_to_freeze_tasks(false)).
     *
     * Instead, we freeze it after it's done its job of encrypting the sensitive processes.
     */
	current->flags |= PF_NOFREEZE;
    
    while (true) {

        wait_for_completion(&args->sensitive_processes_frozen);
        init_completion(&args->sensitive_processes_frozen);

        MY_PRINTK("%s:%i @ %s:\n" 
                "  current->tcm_resident = %i\n"
                , __FILE__, __LINE__, __func__
                , current->tcm_resident
                );

        printk("SUSPEND: begin encryption\n");
        encrypt_task_and_update_pte();
        printk("SUSPEND: done encryption\n");

        args->return_code = 0;

        complete(&args->suspend_crypto_thread_done);

        /* current->flags &= ~PF_NOFREEZE; */
        /* try_to_freeze(); */
        // TODO: 
        // - we need to be unfrozen before any of the sensitive processes so we can decrypt them.
        // - we need to have our flag set back to PF_NOFREEZE in the right place (to prevent 
        //   being unfrozen like sensitive processes in normal code path?)
        /* current->flags &= ~PF_NOFREEZE; */

    }

    do_exit(0);
    return 0;
}
static int encrypt_sensitive_processes(void)
{
    complete(&_args.sensitive_processes_frozen);
    wait_for_completion(&_args.suspend_crypto_thread_done);
    init_completion(&_args.suspend_crypto_thread_done);
    return 0;
}
static int setup_suspend_crypto_thread(void)
{
    int ret = 0;

    init_args();

    suspend_crypto_thread = kthread_create(do_suspend_crypto_thread, &_args, "do_suspend_crypto_thread");
    MY_PRINTK("%s:%i @ %s:\n" 
            "  suspend_crypto_thread = 0x%p\n"
            , __FILE__, __LINE__, __func__
            , (void *) suspend_crypto_thread
            );
	if (IS_ERR(suspend_crypto_thread)) {
		MY_PRINTK("  %s - kthread_create() failed\n", __func__);
        ret = PTR_ERR(suspend_crypto_thread);
        goto failure;
	}
	wake_up_process(suspend_crypto_thread);

    /* current->tcm_resident = 1; */
    /* // TODO: encrypt kernel thread. */
    /* current->tcm_resident = 0; */

    /* Wait for suspend_crypto_thread to finish.
     */
    /* wait_for_completion(&_args.suspend_crypto_thread_done); */

    return _args.return_code;
failure:
    return ret;
}

/**
 * suspend_enter - Make the system enter the given sleep state.
 * @state: System sleep state to enter.
 * @wakeup: Returns information that the sleep state should not be re-entered.
 *
 * This function should be called after devices have been suspended.
 */
static int suspend_enter(suspend_state_t state, bool *wakeup)
{
	int error;

	if (suspend_ops->prepare) {
		error = suspend_ops->prepare();
		if (error)
			goto Platform_finish;
	}

	error = dpm_suspend_end(PMSG_SUSPEND);
	if (error) {
		printk(KERN_ERR "PM: Some devices failed to power down\n");
		goto Platform_finish;
	}

	if (suspend_ops->prepare_late) {
		error = suspend_ops->prepare_late();
		if (error)
			goto Platform_wake;
	}

	if (suspend_test(TEST_PLATFORM))
		goto Platform_wake;

    error = encrypt_sensitive_processes();
    if (error) {
        MY_PRINTK("%s:%i @ %s:\n" 
               "  encrypt_sensitive_processes failed\n"
            , __FILE__, __LINE__, __func__
            );
		goto Platform_wake;
    }

	error = disable_nonboot_cpus();
	if (error || suspend_test(TEST_CPUS))
		goto Enable_cpus;

	arch_suspend_disable_irqs();
	BUG_ON(!irqs_disabled());

    /* busy_wait(SUSPEND_BUSY_WAIT_SEC); */

	error = syscore_suspend();
	if (!error) {
		*wakeup = pm_wakeup_pending();
		if (!(suspend_test(TEST_CORE) || *wakeup)) {
			error = suspend_ops->enter(state);
			events_check_enabled = false;
		}
		syscore_resume();
	}

	arch_suspend_enable_irqs();
	BUG_ON(irqs_disabled());

 Enable_cpus:
	enable_nonboot_cpus();

 Platform_wake:
	if (suspend_ops->wake)
		suspend_ops->wake();

	dpm_resume_start(PMSG_RESUME);

 Platform_finish:
	if (suspend_ops->finish)
		suspend_ops->finish();

	return error;
}

/**
 * suspend_devices_and_enter - Suspend devices and enter system sleep state.
 * @state: System sleep state to enter.
 */
int suspend_devices_and_enter(suspend_state_t state)
{
	int error;
	bool wakeup = false;

	if (!suspend_ops)
		return -ENOSYS;

	trace_machine_suspend(state);
	if (suspend_ops->begin) {
		error = suspend_ops->begin(state);
		if (error)
			goto Close;
	}
	suspend_console();
	suspend_test_start();
	error = dpm_suspend_start(PMSG_SUSPEND);
	if (error) {
		printk(KERN_ERR "PM: Some devices failed to suspend\n");
		goto Recover_platform;
	}
	suspend_test_finish("suspend devices");
	if (suspend_test(TEST_DEVICES))
		goto Recover_platform;

	do {
		error = suspend_enter(state, &wakeup);
	} while (!error && !wakeup
		&& suspend_ops->suspend_again && suspend_ops->suspend_again());

 Resume_devices:
	suspend_test_start();
	dpm_resume_end(PMSG_RESUME);
	suspend_test_finish("resume devices");
	resume_console();
 Close:
	if (suspend_ops->end)
		suspend_ops->end();
	trace_machine_suspend(PWR_EVENT_EXIT);
	return error;

 Recover_platform:
	if (suspend_ops->recover)
		suspend_ops->recover();
	goto Resume_devices;
}

/**
 * suspend_finish - Clean up before finishing the suspend sequence.
 *
 * Call platform code to clean up, restart processes, and free the console that
 * we've allocated. This routine is not called for hibernation.
 */
static void suspend_finish(void)
{
	suspend_thaw_processes();
	pm_notifier_call_chain(PM_POST_SUSPEND);
	pm_restore_console();
    notify_suspend();
}

/**
 * enter_state - Do common work needed to enter system sleep state.
 * @state: System sleep state to enter.
 *
 * Make sure that no one else is trying to put the system into a sleep state.
 * Fail if that's not the case.  Otherwise, prepare for system suspend, make the
 * system enter the given sleep state and clean up after wakeup.
 */
static int enter_state(suspend_state_t state)
{
	int error;

	if (!valid_state(state))
		return -ENODEV;

	if (!mutex_trylock(&pm_mutex))
		return -EBUSY;

	printk(KERN_INFO "PM: Syncing filesystems ... ");
	sys_sync();
	printk("done.\n");

	pr_debug("PM: Preparing system for %s sleep\n", pm_states[state]);
	error = suspend_prepare();
	if (error)
		goto Unlock;

	if (suspend_test(TEST_FREEZER))
		goto Finish;

	pr_debug("PM: Entering %s sleep\n", pm_states[state]);
	pm_restrict_gfp_mask();
	error = suspend_devices_and_enter(state);
	pm_restore_gfp_mask();

 Finish:
	pr_debug("PM: Finishing wakeup.\n");
	suspend_finish();
 Unlock:
	mutex_unlock(&pm_mutex);
	return error;
}

static void pm_suspend_marker(char *annotation)
{
	struct timespec ts;
	struct rtc_time tm;

	getnstimeofday(&ts);
	rtc_time_to_tm(ts.tv_sec, &tm);
	pr_info("PM: suspend %s %d-%02d-%02d %02d:%02d:%02d.%09lu UTC\n",
		annotation, tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
		tm.tm_hour, tm.tm_min, tm.tm_sec, ts.tv_nsec);
}

/**
 * pm_suspend - Externally visible function for suspending the system.
 * @state: System sleep state to enter.
 *
 * Check if the value of @state represents one of the supported states,
 * execute enter_state() and update system suspend statistics.
 */
int pm_suspend(suspend_state_t state)
{
	int error;

	if (state <= PM_SUSPEND_ON || state >= PM_SUSPEND_MAX)
		return -EINVAL;

	pm_suspend_marker("entry");
	error = enter_state(state);
	if (error) {
		suspend_stats.fail++;
		dpm_save_failed_errno(error);
	} else {
		suspend_stats.success++;
	}
	pm_suspend_marker("exit");
	return error;
}
EXPORT_SYMBOL(pm_suspend);

static int suspend_init(void)
{
    int ret;
    ret = setup_suspend_crypto_thread();
    return ret;
}

core_initcall(suspend_init);
