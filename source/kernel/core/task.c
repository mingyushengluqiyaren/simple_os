﻿#include "comm/cpu_instr.h"
#include "core/task.h"
#include "tools/klib.h"
#include "tools/log.h"
#include "os_cfg.h"
#include "cpu/irq.h"
#include "core/memory.h"
#include "cpu/cpu.h"
#include "cpu/mmu.h"
#include "core/syscall.h"
#include "comm/elf.h"
#include "fs/fs.h"

static task_manager_t task_manager;               // 任务管理器
static uint32_t idle_task_stack[IDLE_STACK_SIZE]; // 空闲任务堆栈
static task_t task_table[TASK_NR];                // 用户进程表
static mutex_t task_table_mutex;                  // 进程表互斥访问锁

static int tss_init(task_t *task, int flag, uint32_t entry, uint32_t esp)
{
    int tss_sel = gdt_alloc_desc();
    if (tss_sel < 0)
    {
        log_printf("alloc tss failed.\n");
        return -1;
    }

    segment_desc_set(tss_sel, (uint32_t)&task->tss, sizeof(tss_t),
                     SEG_P_PRESENT | SEG_DPL0 | SEG_TYPE_TSS);

    // tss段初始化
    kernel_memset(&task->tss, 0, sizeof(tss_t));

    // 分配内核栈
    uint32_t kernel_stack = memory_alloc_page();
    if (kernel_stack == 0)
    {
        goto tss_init_failed;
    }

    // 根据不同的权限选择不同的访问选择子
    int code_sel, data_sel;
    if (flag & TASK_FLAG_SYSTEM)
    {
        code_sel = KERNEL_SELECTOR_CS;
        data_sel = KERNEL_SELECTOR_DS;
    }
    else
    {
        code_sel = task_manager.app_code_sel | SEG_RPL3;
        data_sel = task_manager.app_data_sel | SEG_RPL3;
    }

    task->tss.eip = entry;
    task->tss.esp = esp ? esp : kernel_stack + MEM_PAGE_SIZE;
    task->tss.esp0 = kernel_stack + MEM_PAGE_SIZE;
    task->tss.ss0 = KERNEL_SELECTOR_DS;
    task->tss.eip = entry;
    task->tss.eflags = EFLAGS_DEFAULT | EFLAGS_IF;
    task->tss.es = task->tss.ss = task->tss.ds = task->tss.fs = task->tss.gs = data_sel;
    task->tss.cs = code_sel;
    task->tss.iomap = 0;

    uint32_t page_dir = memory_create_uvm();
    if (page_dir == 0)
    {
        goto tss_init_failed;
    }
    task->tss.cr3 = page_dir;

    task->tss_sel = tss_sel;
    return 0;
tss_init_failed:
    gdt_free_sel(tss_sel);

    if (kernel_stack)
    {
        memory_free_page(kernel_stack);
    }
    return -1;
}

/**
 * @brief 初始化任务
 */
int task_init(task_t *task, const char *name, int flag, uint32_t entry, uint32_t esp)
{
    ASSERT(task != (task_t *)0);

    int err = tss_init(task, flag, entry, esp);
    if (err < 0)
    {
        log_printf("init task failed.\n");
        return err;
    }

    kernel_strncpy(task->name, name, TASK_NAME_SIZE);
    task->state = TASK_CREATED;
    task->sleep_ticks = 0;
    task->time_slice = TASK_TIME_SLICE_DEFAULT;
    task->slice_ticks = task->time_slice;
    task->parent = (task_t *)0;
    task->heap_start = 0;
    task->heap_end = 0;
    list_node_init(&task->all_node);
    list_node_init(&task->run_node);
    list_node_init(&task->wait_node);

    kernel_memset(task->file_table, 0, sizeof(task->file_table));

    irq_state_t state = irq_enter_protection();
    task->pid = (uint32_t)task;
    list_insert_last(&task_manager.task_list, &task->all_node);
    irq_leave_protection(state);
    return 0;
}

/**
 * @brief 启动任务
 */
void task_start(task_t *task)
{
    irq_state_t state = irq_enter_protection();
    task_set_ready(task);
    irq_leave_protection(state);
}

/**
 * @brief 任务任务初始时分配的各项资源
 */
void task_uninit(task_t *task)
{
    if (task->tss_sel)
    {
        gdt_free_sel(task->tss_sel);
    }

    if (task->tss.esp0)
    {
        memory_free_page(task->tss.esp0 - MEM_PAGE_SIZE);
    }

    if (task->tss.cr3)
    {
        memory_destroy_uvm(task->tss.cr3);
    }

    kernel_memset(task, 0, sizeof(task_t));
}

void simple_switch(uint32_t **from, uint32_t *to);

/**
 * @brief 切换至指定任务
 */
void task_switch_from_to(task_t *from, task_t *to)
{
    switch_to_tss(to->tss_sel);
}

/**
 * @brief 初始进程的初始化
 */
void task_first_init(void)
{
    void first_task_entry(void);

    extern uint8_t s_first_task[], e_first_task[];

    uint32_t copy_size = (uint32_t)(e_first_task - s_first_task);
    uint32_t alloc_size = 10 * MEM_PAGE_SIZE;
    ASSERT(copy_size < alloc_size);

    uint32_t first_start = (uint32_t)first_task_entry;

    task_init(&task_manager.first_task, "first task", 0, first_start, first_start + alloc_size);
    task_manager.first_task.heap_start = (uint32_t)e_first_task;
    task_manager.first_task.heap_end = task_manager.first_task.heap_start;
    task_manager.curr_task = &task_manager.first_task;

    mmu_set_page_dir(task_manager.first_task.tss.cr3);

    memory_alloc_page_for(first_start, alloc_size, PTE_P | PTE_W | PTE_U);
    kernel_memcpy((void *)first_start, (void *)&s_first_task, copy_size);

    task_start(&task_manager.first_task);

    write_tr(task_manager.first_task.tss_sel);
}

/**
 * @brief 返回初始任务
 */
task_t *task_first_task(void)
{
    return &task_manager.first_task;
}

/**
 * @brief 空闲任务
 */
static void idle_task_entry(void)
{
    for (;;)
    {
        hlt();
    }
}

/**
 * @brief 任务管理器初始化
 */
void task_manager_init(void)
{
    kernel_memset(task_table, 0, sizeof(task_table));
    mutex_init(&task_table_mutex);

    int sel = gdt_alloc_desc();
    segment_desc_set(sel, 0x00000000, 0xFFFFFFFF,
                     SEG_P_PRESENT | SEG_DPL3 | SEG_S_NORMAL |
                         SEG_TYPE_DATA | SEG_TYPE_RW | SEG_D);
    task_manager.app_data_sel = sel;

    sel = gdt_alloc_desc();
    segment_desc_set(sel, 0x00000000, 0xFFFFFFFF,
                     SEG_P_PRESENT | SEG_DPL3 | SEG_S_NORMAL |
                         SEG_TYPE_CODE | SEG_TYPE_RW | SEG_D);
    task_manager.app_code_sel = sel;

    // 各队列初始化
    list_init(&task_manager.ready_list);
    list_init(&task_manager.task_list);
    list_init(&task_manager.sleep_list);

    // 空闲任务初始化
    task_init(&task_manager.idle_task,
              "idle task",
              TASK_FLAG_SYSTEM,
              (uint32_t)idle_task_entry,
              0);
    task_manager.curr_task = (task_t *)0;
    task_start(&task_manager.idle_task);
}

/**
 * @brief 将任务插入就绪队列
 */
void task_set_ready(task_t *task)
{
    if (task != &task_manager.idle_task)
    {
        list_insert_last(&task_manager.ready_list, &task->run_node);
        task->state = TASK_READY;
    }
}

/**
 * @brief 将任务从就绪队列移除
 */
void task_set_block(task_t *task)
{
    if (task != &task_manager.idle_task)
    {
        list_remove(&task_manager.ready_list, &task->run_node);
    }
}
/**
 * @brief 获取下一将要运行的任务
 */
static task_t *task_next_run(void)
{
    if (list_count(&task_manager.ready_list) == 0)
    {
        return &task_manager.idle_task;
    }

    list_node_t *task_node = list_first(&task_manager.ready_list);
    return list_node_parent(task_node, task_t, run_node);
}

/**
 * @brief 将任务加入睡眠状态
 */
void task_set_sleep(task_t *task, uint32_t ticks)
{
    if (ticks <= 0)
    {
        return;
    }

    task->sleep_ticks = ticks;
    task->state = TASK_SLEEP;
    list_insert_last(&task_manager.sleep_list, &task->run_node);
}

/**
 * @brief 将任务从延时队列移除
 *
 * @param task
 */
void task_set_wakeup(task_t *task)
{
    list_remove(&task_manager.sleep_list, &task->run_node);
}

/**
 * @brief 获取当前正在运行的任务
 */
task_t *task_current(void)
{
    return task_manager.curr_task;
}

/**
 * @brief 获取当前进程指定的文件描述符
 */
file_t *task_file(int fd)
{
    if ((fd >= 0) && (fd < TASK_OFILE_NR))
    {
        file_t *file = task_current()->file_table[fd];
        return file;
    }

    return (file_t *)0;
}

/**
 * @brief 为指定的file分配一个新的文件id
 */
int task_alloc_fd(file_t *file)
{
    task_t *task = task_current();

    for (int i = 0; i < TASK_OFILE_NR; i++)
    {
        file_t *p = task->file_table[i];
        if (p == (file_t *)0)
        {
            task->file_table[i] = file;
            return i;
        }
    }

    return -1;
}

/**
 * @brief 移除任务中打开的文件fd
 */
void task_remove_fd(int fd)
{
    if ((fd >= 0) && (fd < TASK_OFILE_NR))
    {
        task_current()->file_table[fd] = (file_t *)0;
    }
}

/**
 * @brief 当前任务主动放弃CPU
 */
int sys_yield(void)
{
    irq_state_t state = irq_enter_protection();

    if (list_count(&task_manager.ready_list) > 1)
    {
        task_t *curr_task = task_current();
        task_set_block(curr_task);
        task_set_ready(curr_task);

        task_dispatch();
    }
    irq_leave_protection(state);

    return 0;
}

/**
 * @brief 进行一次任务调度
 */
void task_dispatch(void)
{
    task_t *to = task_next_run();
    if (to != task_manager.curr_task)
    {
        task_t *from = task_manager.curr_task;

        task_manager.curr_task = to;
        task_switch_from_to(from, to);
    }
}

/**
 * @brief 时间处理
 */
void task_time_tick(void)
{
    task_t *curr_task = task_current();

    irq_state_t state = irq_enter_protection();
    if (--curr_task->slice_ticks == 0)
    {
        curr_task->slice_ticks = curr_task->time_slice;
        task_set_block(curr_task);
        task_set_ready(curr_task);
    }

    // 睡眠处理
    list_node_t *curr = list_first(&task_manager.sleep_list);
    while (curr)
    {
        list_node_t *next = list_node_next(curr);

        task_t *task = list_node_parent(curr, task_t, run_node);
        if (--task->sleep_ticks == 0)
        {
            task_set_wakeup(task);
            task_set_ready(task);
        }
        curr = next;
    }

    task_dispatch();
    irq_leave_protection(state);
}

/**
 * @brief 分配一个任务结构
 */
static task_t *alloc_task(void)
{
    task_t *task = (task_t *)0;

    mutex_lock(&task_table_mutex);
    for (int i = 0; i < TASK_NR; i++)
    {
        task_t *curr = task_table + i;
        if (curr->name[0] == 0)
        {
            task = curr;
            break;
        }
    }
    mutex_unlock(&task_table_mutex);

    return task;
}

/**
 * @brief 释放任务结构
 */
static void free_task(task_t *task)
{
    mutex_lock(&task_table_mutex);
    task->name[0] = 0;
    mutex_unlock(&task_table_mutex);
}

/**
 * @brief 任务进入睡眠状态
 *
 * @param ms
 */
void sys_msleep(uint32_t ms)
{
    if (ms < OS_TICK_MS)
    {
        ms = OS_TICK_MS;
    }

    irq_state_t state = irq_enter_protection();

    // 从就绪队列移除，加入睡眠队列
    task_set_block(task_manager.curr_task);
    task_set_sleep(task_manager.curr_task, (ms + (OS_TICK_MS - 1)) / OS_TICK_MS);
    task_dispatch();
    irq_leave_protection(state);
}

/**
 * @brief 从当前进程中拷贝已经打开的文件列表
 */
static void copy_opened_files(task_t *child_task)
{
    task_t *parent = task_current();

    for (int i = 0; i < TASK_OFILE_NR; i++)
    {
        file_t *file = parent->file_table[i];
        if (file)
        {
            file_inc_ref(file);
            child_task->file_table[i] = parent->file_table[i];
        }
    }
}

/**
 * @brief 创建进程的副本
 */
int sys_fork(void)
{
    task_t *parent_task = task_current();

    // 分配任务结构
    task_t *child_task = alloc_task();
    if (child_task == (task_t *)0)
    {
        goto fork_failed;
    }

    syscall_frame_t *frame = (syscall_frame_t *)(parent_task->tss.esp0 - sizeof(syscall_frame_t));
    int err = task_init(child_task, parent_task->name, 0, frame->eip,
                        frame->esp + sizeof(uint32_t) * SYSCALL_PARAM_COUNT);
    if (err < 0)
    {
        goto fork_failed;
    }

    // 拷贝打开的文件
    copy_opened_files(child_task);
    tss_t *tss = &child_task->tss;
    tss->eax = 0;
    tss->ebx = frame->ebx;
    tss->ecx = frame->ecx;
    tss->edx = frame->edx;
    tss->esi = frame->esi;
    tss->edi = frame->edi;
    tss->ebp = frame->ebp;

    tss->cs = frame->cs;
    tss->ds = frame->ds;
    tss->es = frame->es;
    tss->fs = frame->fs;
    tss->gs = frame->gs;
    tss->eflags = frame->eflags;
    child_task->parent = parent_task;
    if ((child_task->tss.cr3 = memory_copy_uvm(parent_task->tss.cr3)) < 0)
    {
        goto fork_failed;
    }

    // 创建成功，返回子进程的pid
    task_start(child_task);
    return child_task->pid;
fork_failed:
    if (child_task)
    {
        task_uninit(child_task);
        free_task(child_task);
    }
    return -1;
}

/**
 * @brief 加载一个程序表头的数据到内存中
 */
static int load_phdr(int file, Elf32_Phdr *phdr, uint32_t page_dir)
{
    ASSERT((phdr->p_vaddr & (MEM_PAGE_SIZE - 1)) == 0);

    // 分配空间
    int err = memory_alloc_for_page_dir(page_dir, phdr->p_vaddr, phdr->p_memsz, PTE_P | PTE_U | PTE_W);
    if (err < 0)
    {
        log_printf("no memory");
        return -1;
    }

    // 调整当前的读写位置
    if (sys_lseek(file, phdr->p_offset, 0) < 0)
    {
        log_printf("read file failed");
        return -1;
    }
    uint32_t vaddr = phdr->p_vaddr;
    uint32_t size = phdr->p_filesz;
    while (size > 0)
    {
        int curr_size = (size > MEM_PAGE_SIZE) ? MEM_PAGE_SIZE : size;
        uint32_t paddr = memory_get_paddr(page_dir, vaddr);
        if (sys_read(file, (char *)paddr, curr_size) < curr_size)
        {
            log_printf("read file failed");
            return -1;
        }

        size -= curr_size;
        vaddr += curr_size;
    }
    return 0;
}

/**
 * @brief 加载elf文件到内存中
 */
static uint32_t load_elf_file(task_t *task, const char *name, uint32_t page_dir)
{
    Elf32_Ehdr elf_hdr;
    Elf32_Phdr elf_phdr;

    int file = sys_open(name, 0);
    if (file < 0)
    {
        log_printf("open file failed.%s", name);
        goto load_failed;
    }

    // 先读取文件头
    int cnt = sys_read(file, (char *)&elf_hdr, sizeof(Elf32_Ehdr));
    if (cnt < sizeof(Elf32_Ehdr))
    {
        log_printf("elf hdr too small. size=%d", cnt);
        goto load_failed;
    }

    if ((elf_hdr.e_ident[0] != ELF_MAGIC) || (elf_hdr.e_ident[1] != 'E') || (elf_hdr.e_ident[2] != 'L') || (elf_hdr.e_ident[3] != 'F'))
    {
        log_printf("check elf indent failed.");
        goto load_failed;
    }
    if ((elf_hdr.e_type != ET_EXEC) || (elf_hdr.e_machine != ET_386) || (elf_hdr.e_entry == 0))
    {
        log_printf("check elf type or entry failed.");
        goto load_failed;
    }
    if ((elf_hdr.e_phentsize == 0) || (elf_hdr.e_phoff == 0))
    {
        log_printf("none programe header");
        goto load_failed;
    }

    uint32_t e_phoff = elf_hdr.e_phoff;
    for (int i = 0; i < elf_hdr.e_phnum; i++, e_phoff += elf_hdr.e_phentsize)
    {
        if (sys_lseek(file, e_phoff, 0) < 0)
        {
            log_printf("read file failed");
            goto load_failed;
        }

        cnt = sys_read(file, (char *)&elf_phdr, sizeof(Elf32_Phdr));
        if (cnt < sizeof(Elf32_Phdr))
        {
            log_printf("read file failed");
            goto load_failed;
        }

        if ((elf_phdr.p_type != PT_LOAD) || (elf_phdr.p_vaddr < MEMORY_TASK_BASE))
        {
            continue;
        }

        int err = load_phdr(file, &elf_phdr, page_dir);
        if (err < 0)
        {
            log_printf("load program hdr failed");
            goto load_failed;
        }

        task->heap_start = elf_phdr.p_vaddr + elf_phdr.p_memsz;
        task->heap_end = task->heap_start;
    }

    sys_close(file);
    return elf_hdr.e_entry;

load_failed:
    if (file >= 0)
    {
        sys_close(file);
    }

    return 0;
}

/**
 * @brief 复制进程参数到栈中。注意argv和env指向的空间在另一个页表里
 */
static int copy_args(char *to, uint32_t page_dir, int argc, char **argv)
{
    task_args_t task_args;
    task_args.argc = argc;
    task_args.argv = (char **)(to + sizeof(task_args_t));
    char *dest_arg = to + sizeof(task_args_t) + sizeof(char *) * (argc + 1);
    char **dest_argv_tb = (char **)memory_get_paddr(page_dir, (uint32_t)(to + sizeof(task_args_t)));
    ASSERT(dest_argv_tb != 0);

    for (int i = 0; i < argc; i++)
    {
        char *from = argv[i];
        int len = kernel_strlen(from) + 1; // 包含结束符
        int err = memory_copy_uvm_data((uint32_t)dest_arg, page_dir, (uint32_t)from, len);
        ASSERT(err >= 0);
        dest_argv_tb[i] = dest_arg;
        dest_arg += len;
    }
    if (argc)
    {
        dest_argv_tb[argc] = '\0';
    }
    return memory_copy_uvm_data((uint32_t)to, page_dir, (uint32_t)&task_args, sizeof(task_args_t));
}

/**
 * @brief 加载一个进程
 */
int sys_execve(char *name, char **argv, char **env)
{
    task_t *task = task_current();
    kernel_strncpy(task->name, get_file_name(name), TASK_NAME_SIZE);
    uint32_t old_page_dir = task->tss.cr3;
    uint32_t new_page_dir = memory_create_uvm();
    if (!new_page_dir)
    {
        goto exec_failed;
    }
    uint32_t entry = load_elf_file(task, name, new_page_dir);
    if (entry == 0)
    {
        goto exec_failed;
    }

    uint32_t stack_top = MEM_TASK_STACK_TOP - MEM_TASK_ARG_SIZE;
    int err = memory_alloc_for_page_dir(new_page_dir,
                                        MEM_TASK_STACK_TOP - MEM_TASK_STACK_SIZE,
                                        MEM_TASK_STACK_SIZE, PTE_P | PTE_U | PTE_W);
    if (err < 0)
    {
        goto exec_failed;
    }

    int argc = strings_count(argv);
    err = copy_args((char *)stack_top, new_page_dir, argc, argv);
    if (err < 0)
    {
        goto exec_failed;
    }
    syscall_frame_t *frame = (syscall_frame_t *)(task->tss.esp0 - sizeof(syscall_frame_t));
    frame->eip = entry;
    frame->eax = frame->ebx = frame->ecx = frame->edx = 0;
    frame->esi = frame->edi = frame->ebp = 0;
    frame->eflags = EFLAGS_DEFAULT | EFLAGS_IF;

    frame->esp = stack_top - sizeof(uint32_t) * SYSCALL_PARAM_COUNT;

    // 切换到新的页表
    task->tss.cr3 = new_page_dir;
    mmu_set_page_dir(new_page_dir);
    memory_destroy_uvm(old_page_dir);
    return 0;

exec_failed: // 必要的资源释放
    if (new_page_dir)
    {
        task->tss.cr3 = old_page_dir;
        mmu_set_page_dir(old_page_dir);
        memory_destroy_uvm(new_page_dir);
    }

    return -1;
}

/**
 * 返回任务的pid
 */
int sys_getpid(void)
{
    task_t *curr_task = task_current();
    return curr_task->pid;
}

/**
 * @brief 等待子进程退出
 */
int sys_wait(int *status)
{
    task_t *curr_task = task_current();

    for (;;)
    {
        mutex_lock(&task_table_mutex);
        for (int i = 0; i < TASK_NR; i++)
        {
            task_t *task = task_table + i;
            if (task->parent != curr_task)
            {
                continue;
            }

            if (task->state == TASK_ZOMBIE)
            {
                int pid = task->pid;

                *status = task->status;

                memory_destroy_uvm(task->tss.cr3);
                memory_free_page(task->tss.esp0 - MEM_PAGE_SIZE);
                kernel_memset(task, 0, sizeof(task_t));

                mutex_unlock(&task_table_mutex);
                return pid;
            }
        }
        mutex_unlock(&task_table_mutex);

        irq_state_t state = irq_enter_protection();
        task_set_block(curr_task);
        curr_task->state = TASK_WAITING;
        task_dispatch();
        irq_leave_protection(state);
    }
}

/**
 * @brief 退出进程
 */
void sys_exit(int status)
{
    task_t *curr_task = task_current();
    for (int fd = 0; fd < TASK_OFILE_NR; fd++)
    {
        file_t *file = curr_task->file_table[fd];
        if (file)
        {
            sys_close(fd);
            curr_task->file_table[fd] = (file_t *)0;
        }
    }

    int move_child = 0;
    mutex_lock(&task_table_mutex);
    for (int i = 0; i < TASK_OFILE_NR; i++)
    {
        task_t *task = task_table + i;
        if (task->parent == curr_task)
        {
            // 有子进程，则转给init_task
            task->parent = &task_manager.first_task;
            if (task->state == TASK_ZOMBIE)
            {
                move_child = 1;
            }
        }
    }
    mutex_unlock(&task_table_mutex);

    irq_state_t state = irq_enter_protection();

    // 如果有移动子进程，则唤醒init进程
    task_t *parent = curr_task->parent;
    if (move_child && (parent != &task_manager.first_task))
    {
        if (task_manager.first_task.state == TASK_WAITING)
        {
            task_set_ready(&task_manager.first_task);
        }
    }

    if (parent->state == TASK_WAITING)
    {
        task_set_ready(curr_task->parent);
    }

    curr_task->status = status;
    curr_task->state = TASK_ZOMBIE;
    task_set_block(curr_task);
    task_dispatch();

    irq_leave_protection(state);
}

int sys_ps(int status)
{
    if (status == 0)
    {
        list_node_t *node = task_manager.task_list.first;
        while (node)
        {
            task_t *task = list_node_parent(node, task_t, all_node);
            log_printf("task name: %s, pid: %d, state: %d\n", task->name, task->pid, task->state);
            node = node->next;
        }
    }
    else if (status == 1)
    {
        list_node_t *node = task_manager.ready_list.first;
        while (node)
        {
            task_t *task = list_node_parent(node, task_t, run_node);
            log_printf("running task name: %s, pid: %d, state: %d\n", task->name, task->pid, task->state);
            node = node->next;
        }
    }
    else if (status == 2)
    {
        list_node_t *node = task_manager.sleep_list.first;
        while (node)
        {
            task_t *task = list_node_parent(node, task_t, wait_node);
            log_printf("sleeping task name: %s, pid: %d, state: %d\n", task->name, task->pid, task->state);
            node = node->next;
        }
    }
}