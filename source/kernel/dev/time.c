#include "dev/time.h"
#include "cpu/irq.h"
#include "comm/cpu_instr.h"
#include "os_cfg.h"
#include "core/task.h"

static uint32_t sys_tick;

/**
 * 定时器中断处理函数
 */
void do_handler_timer(exception_frame_t *frame)
{
    sys_tick++;
    pic_send_eoi(IRQ0_TIMER);

    task_time_tick();
}

/**
 * 初始化硬件定时器
 */
static void init_pit(void)
{
    uint32_t reload_count = PIT_OSC_FREQ / (1000.0 / OS_TICK_MS);
    outb(PIT_COMMAND_MODE_PORT, PIT_CHANNLE0 | PIT_LOAD_LOHI | PIT_MODE3);
    outb(PIT_CHANNEL0_DATA_PORT, reload_count & 0xFF);
    outb(PIT_CHANNEL0_DATA_PORT, (reload_count >> 8) & 0xFF);

    irq_install(IRQ0_TIMER, (irq_handler_t)exception_handler_timer);
    irq_enable(IRQ0_TIMER);
}

/**
 * 定时器初始化
 */
void time_init(void)
{
    sys_tick = 0;

    init_pit();
}
