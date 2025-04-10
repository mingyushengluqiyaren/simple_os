#include <stdio.h>
#include <string.h>
#include "lib_syscall.h"
#include "main.h"
#include <getopt.h>
#include <stdlib.h>
#include <sys/file.h>
#include "fs/file.h"
#include "dev/tty.h"
#include "core/task.h"

static cli_t cli;
static const char *promote = "user >>"; // 命令行提示符
#define OS_VERSION "1.0.1"

/**
 * 显示命令行提示符
 */
static void show_promote(void)
{
    printf("%s", cli.promote);
    fflush(stdout);
}

/**
 * help命令
 */
static int do_help(int argc, char **argv)
{
    const cli_cmd_t *start = cli.cmd_start;
    while (start < cli.cmd_end)
    {
        printf("%s %s\n", start->name, start->description);
        start++;
    }
    return 0;
}

/**
 * 清屏命令
 */
static int do_clear(int argc, char **argv)
{
    printf("%s", ESC_CLEAR_SCREEN);
    printf("%s", ESC_MOVE_CURSOR(0, 0));
    return 0;
}

/**
 * 回显命令
 */
static int do_echo(int argc, char **argv)
{
    if (argc == 1)
    {
        char msg_buf[128];

        fgets(msg_buf, sizeof(msg_buf), stdin);
        msg_buf[sizeof(msg_buf) - 1] = '\0';
        puts(msg_buf);
        return 0;
    }

    int count = 1;
    int ch;
    while ((ch = getopt(argc, argv, "n:h")) != -1)
    {
        switch (ch)
        {
        case 'h':
            puts("echo echo any message");
            puts("Usage: echo [-n count] msg");
            optind = 1;
            return 0;
        case 'n':
            count = atoi(optarg);
            break;
        case '?':
            if (optarg)
            {
                fprintf(stderr, "Unknown option: -%s\n", optarg);
            }
            optind = 1;
            return -1;
        }
    }
    if (optind > argc - 1)
    {
        fprintf(stderr, "Message is empty \n");
        optind = 1;
        return -1;
    }
    char *msg = argv[optind];
    for (int i = 0; i < count; i++)
    {
        puts(msg);
    }
    optind = 1;
    return 0;
}

/**
 * 程序退出命令
 */
static int do_exit(int argc, char **argv)
{
    exit(0);
    return 0;
}

/**
 * @brief 列出文本文件内容
 */
static int do_less(int argc, char **argv)
{
    int line_mode = 0;

    int ch;
    while ((ch = getopt(argc, argv, "lh")) != -1)
    {
        switch (ch)
        {
        case 'h':
            puts("show file content");
            puts("less [-l] file");
            puts("-l show file line by line.");
            break;
        case 'l':
            line_mode = 1;
            break;
        case '?':
            if (optarg)
            {
                fprintf(stderr, "Unknown option: -%s\n", optarg);
            }
            optind = 1;
            return -1;
        }
    }
    if (optind > argc - 1)
    {
        fprintf(stderr, "no file\n");
        optind = 1;
        return -1;
    }

    FILE *file = fopen(argv[optind], "r");
    if (file == NULL)
    {
        fprintf(stderr, "open file failed. %s", argv[optind]);
        optind = 1;
        return -1;
    }

    char *buf = (char *)malloc(255);

    if (line_mode == 0)
    {
        while (fgets(buf, 255, file) != NULL)
        {
            fputs(buf, stdout);
        }
    }
    else
    {
        // 不使用缓存
        setvbuf(stdin, NULL, _IONBF, 0);
        ioctl(0, TTY_CMD_ECHO, 0, 0);
        while (1)
        {
            char *b = fgets(buf, 255, file);
            if (b == NULL)
            {
                break;
            }
            fputs(buf, stdout);

            int ch;
            while ((ch = fgetc(stdin)) != 'n')
            {
                if (ch == 'q')
                {
                    goto less_quit;
                }
            }
        }
    less_quit:
        // 恢复为行缓存
        setvbuf(stdin, NULL, _IOLBF, BUFSIZ);
        ioctl(0, TTY_CMD_ECHO, 1, 0);
    }
    free(buf);
    fclose(file);
    optind = 1; // getopt需要多次调用，需要重置
    return 0;
}

/**
 * @brief 列出目录内容
 */
static int do_ls(int argc, char **argv)
{
    // 打开目录
    DIR *p_dir = opendir("temp");
    if (p_dir == NULL)
    {
        printf("open dir failed\n");
        return -1;
    }

    // 然后进行遍历
    struct dirent *entry;
    while ((entry = readdir(p_dir)) != NULL)
    {
        strlwr(entry->name);
        printf("%c %s %d\n",
               entry->type == FILE_DIR ? 'd' : 'f',
               entry->name,
               entry->size);
    }
    closedir(p_dir);

    return 0;
}

static int do_cp(int argc, char **argv)
{
    if (argc < 3)
    {
        puts("no [from] or no [to]");
        return -1;
    }

    FILE *from, *to;
    from = fopen(argv[1], "rb");
    to = fopen(argv[2], "wb");
    if (!from || !to)
    {
        puts("open file failed.");
        goto ls_failed;
    }

    char *buf = (char *)malloc(255);
    int size = 0;
    while ((size = fread(buf, 1, 255, from)) > 0)
    {
        fwrite(buf, 1, size, to);
    }
    free(buf);

ls_failed:
    if (from)
    {
        fclose(from);
    }
    if (to)
    {
        fclose(to);
    }
    return 0;
}

/**
 * @brief 删除文件命令
 */
static int do_remove(int argc, char **argv)
{
    if (argc < 2)
    {
        fprintf(stderr, "no file");
        return -1;
    }

    int err = unlink(argv[1]);
    if (err < 0)
    {
        fprintf(stderr, "rm file failed: %s", argv[1]);
        return err;
    }

    return 0;
}

/**
 * @brief 显示所有进程
 */

static int do_ps(int argc, char **argv)
{
    int show_running = 0; // 默认不显示运行中的进程
    int ch;

    // 解析参数
    while ((ch = getopt(argc, argv, "r")) != -1)
    {
        switch (ch)
        {
        case 'r':
            show_running = 1; // 如果用户传入 -r，设置标志位
            break;
        default:
            show_running = 0;
            break;
        }
    }
    optind = 1; // getopt需要多次调用，需要重置
    int err = ps(show_running);
    show_running = 0;
    return err;
}

// 命令列表
static const cli_cmd_t cmd_list[] = {
    {
        .name = "help",
        .description = ":list all commands.",
        .do_func = do_help,
    },
    {
        .name = "clear",
        .description = ":clear the screen.",
        .do_func = do_clear,
    },
    {
        .name = "echo",
        .description = ":display the string.",
        .do_func = do_echo,
    },
    {
        .name = "exit",
        .description = ":exit the shell window.",
        .do_func = do_exit,
    },
    {
        .name = "ls",
        .description = ":list all files.",
        .do_func = do_ls,
    },
    {
        .name = "less",
        .description = ":less [-l]:view the contents of a file.",
        .do_func = do_less,
    },
    {
        .name = "cp",
        .description = ":copy file",
        .do_func = do_cp,
    },
    {
        .name = "rm",
        .description = ":remove file",
        .do_func = do_remove,
    },
    {
        .name = "ps",
        .description = ":show progress information. -r:running processes.",
        .do_func = do_ps,
    },
};

/**
 * 命令行初始化
 */
static void cli_init(const char *promote, const cli_cmd_t *cmd_list, int cnt)
{
    cli.promote = promote;

    memset(cli.curr_input, 0, CLI_INPUT_SIZE);

    cli.cmd_start = cmd_list;
    cli.cmd_end = cmd_list + cnt;
}

/**
 * 在内部命令中搜索
 */
static const cli_cmd_t *find_builtin(const char *name)
{
    for (const cli_cmd_t *cmd = cli.cmd_start; cmd < cli.cmd_end; cmd++)
    {
        if (strcmp(cmd->name, name) != 0)
        {
            continue;
        }

        return cmd;
    }

    return (const cli_cmd_t *)0;
}

/**
 * 运行内部命令
 */
static void run_builtin(const cli_cmd_t *cmd, int argc, char **argv)
{
    int ret = cmd->do_func(argc, argv);
    if (ret < 0)
    {
        fprintf(stderr, ESC_COLOR_ERROR "error: %d\n" ESC_COLOR_DEFAULT, ret);
    }
}

/**
 * 遍历搜索目录，看看文件是否存在，存在返回文件所在路径
 */
static const char *find_exec_path(const char *file_name)
{
    int fd = open(file_name, 0);
    if (fd < 0)
    {
        return (const char *)0;
    }

    close(fd);
    return file_name;
}

/**
 * 试图运行当前文件
 */
static void run_exec_file(const char *path, int argc, char **argv)
{
    int pid = fork();
    if (pid < 0)
    {
        fprintf(stderr, "fork failed: %s", path);
    }
    else if (pid == 0)
    {
        int err = execve(path, argv, (char *const *)0);
        if (err < 0)
        {
            fprintf(stderr, "exec failed: %s", path);
        }
        exit(-1);
    }
    else
    {
        int status;
        int pid = wait(&status);
        fprintf(stderr, "cmd %s result: %d, pid = %d\n", path, status, pid);
    }
}

int main(int argc, char **argv)
{
    msleep(100);
    open(argv[0], O_RDWR);
    dup(0); // 标准输出
    dup(0); // 标准错误输出
    printf("Welcome to myslqyr operating system!\n");
    printf("os version:%s\n", OS_VERSION);
    printf("You can type 'help' to see the commands and how to use them.\n");
    int pid = getpid();

    cli_init(promote, cmd_list, sizeof(cmd_list) / sizeof(cli_cmd_t));
    for (;;)
    {
        show_promote();
        char *str = fgets(cli.curr_input, CLI_INPUT_SIZE, stdin);
        if (str == (char *)0)
        {
            break;
        }

        char *cr = strchr(cli.curr_input, '\n');
        if (cr)
        {
            *cr = '\0';
        }
        cr = strchr(cli.curr_input, '\r');
        if (cr)
        {
            *cr = '\0';
        }

        int argc = 0;
        char *argv[CLI_MAX_ARG_COUNT];
        memset(argv, 0, sizeof(argv));

        const char *space = " ";
        char *token = strtok(cli.curr_input, space);
        while (token)
        {
            argv[argc++] = token;

            token = strtok(NULL, space);
        }
        if (argc == 0)
        {
            continue;
        }

        const cli_cmd_t *cmd = find_builtin(argv[0]);
        if (cmd)
        {
            run_builtin(cmd, argc, argv);
            continue;
        }
        const char *path = find_exec_path(argv[0]);
        if (path)
        {
            run_exec_file(path, argc, argv);
            continue;
        }

        fprintf(stderr, ESC_COLOR_ERROR "Unknown command: %s\n" ESC_COLOR_DEFAULT, cli.curr_input);
    }

    return 0;
}