/*
 * egctl - EnerGenie EM-PMS-LAN control utility
 *
 * Copyright (c) 2014 Vitaly Sinilin <vs@kp4.ru>
 *
 * Published under the terms of the MIT License,
 * see the included COPYING file.
 */

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <pwd.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#define TASK_LEN            4
#define STATCRYP_LEN        4
#define CTRLCRYP_LEN        4
#define KEY_LEN             8

#define STATE_ON            0x11
#define STATE_ON_NO_VOLTAGE 0x12
#define STATE_OFF           0x22
#define STATE_OFF_VOLTAGE   0x21

#define STATE_INVALID       0xFF /* for internal use */

#define V21_STATE_ON        0x41
#define V21_STATE_OFF       0x82

#define SWITCH_ON           0x01
#define SWITCH_OFF          0x02
#define DONT_SWITCH         0x04

#define SOCKET_COUNT 4      /* AC power sockets, not network ones ;) */

#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))

typedef enum
{
    EG_PROTO_V20,
    EG_PROTO_V21
} Protocol;

typedef enum
{
    ACTION_ON,
    ACTION_OFF,
    ACTION_TOGGLE,
    ACTION_LEFT,
    ACTION_INVALID
} Action;

typedef struct
{
    Action socket[SOCKET_COUNT];
} Actions;

typedef struct
{
    uint8_t octets[KEY_LEN];
} Key;

typedef struct
{
    /* since the protocol is little-endian, low word comes first */
    uint16_t loword;
    uint16_t hiword;
} __attribute__((__packed__)) Res;

typedef struct
{
    struct sockaddr_in addr;
    Protocol           proto;
    Key                key;
} Config;

typedef struct
{
    uint8_t socket[SOCKET_COUNT];
} Status, Controls;

typedef struct
{
    uint8_t task[TASK_LEN];
    Key     key;
} Session;

const char *g_egtabs[] =
{
    NULL,           /* placeholder for ~/.egtab */
    "/etc/egtab"
};

void vfatal(const char *fmt, va_list ap)
{
    vfprintf(stderr, fmt, ap);
    fprintf(stderr, "\n");
    exit(EXIT_FAILURE);
}

void fatal(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    vfatal(fmt, ap);
    va_end(ap);
}

void warn(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    fprintf(stderr, "\n");
    va_end(ap);
}

#ifdef DEBUG
void dbg4(const char *name, const uint8_t *buf)
{
    fprintf(stderr, "%8s: 0x%02X 0x%02X 0x%02X 0x%02X\n",
            name, buf[0], buf[1], buf[2], buf[3]);
}
#else
#define dbg4(n,b)
#endif

void xread(int fd, void *buf, size_t count)
{
    ssize_t ret = read(fd, buf, count);

    if (ret == (ssize_t)count) {
        return;
    } else if (ret == -1) {
        if (errno != EINTR)
            fatal("Unable to read from socket: %s", strerror(errno));
        else
            ret = 0;
    }

    xread(fd, (char *)buf + ret, count - ret);
}

void xwrite(int fd, const void *buf, size_t count)
{
    ssize_t ret = write(fd, buf, count);

    if (ret == (ssize_t)count) {
        return;
    } else if (ret == -1) {
        if (errno != EINTR)
            fatal("Unable to write to socket: %s", strerror(errno));
        else
            ret = 0;
    }

    xwrite(fd, (char *)buf + ret, count - ret);
}

char *get_personal_egtab_name(void)
{
    static char egtab[1024] = "/dev/null";
    struct passwd *pwd = getpwuid(getuid());

    if (pwd) {
        snprintf(egtab, sizeof(egtab), "%s/.egtab", pwd->pw_dir);
    } else {
        warn("Unable to determine user home directory");
    }

    return egtab;
}

char *consume_until_whitespace(char **str)
{
    char *tok = *str;

    if (tok) {
        /* strip leading whitespaces */
        tok += strspn(tok, " \t");

        if (*tok == '\0') { /* no tokens */
            *str = NULL;
            tok = NULL;
        } else {
            char *eot = tok + strcspn(tok, " \t");
            if (*eot == '\0') { /* last token */
                *str = NULL;
            } else {
                *eot = '\0';
                *str = eot + 1;
            }
        }
    }

    return tok;
}

Protocol consume_protocol(char **str)
{
    Protocol proto;
    char *tok = consume_until_whitespace(str);

    if (!tok)
        fatal("Protocol isn't specified");

    if (!strcmp(tok, "pms20"))
        proto = EG_PROTO_V20;
    else if (!strcmp(tok, "pms21"))
        proto = EG_PROTO_V21;
    else
        fatal("Unknown protocol %s", tok);

    return proto;
}

in_addr_t consume_ip_address(char **str)
{
    in_addr_t addr;
    char *tok = consume_until_whitespace(str);

    if (!tok)
        fatal("IP address isn't specified");

    addr = inet_addr(tok);

    if (addr == INADDR_NONE) {
        /* It is ok that INADDR_NONE screens 255.255.255.255, since
         * this address isn't appropriate here anyway. */
        fatal("Invalid IP address specified");
    }

    return addr;
}

in_port_t consume_tcp_port(char **str)
{
    char *tok = consume_until_whitespace(str);

    if (!tok)
        fatal("TCP port isn't specified");

    return htons(atoi(tok));
}

Key consume_key(char **str)
{
    Key key;
    size_t keylen;
    char *tok = consume_until_whitespace(str);

    if (!tok)
        fatal("Password isn't specified");

    keylen = strlen(tok);

    if (keylen > KEY_LEN) {
        warn("Password too long, only first %u chars "
             "will be considered", KEY_LEN);
        keylen = KEY_LEN;
    }

    /* Key should be padded with trailing spaces */
    memset(key.octets, 0x20, KEY_LEN);
    memcpy(key.octets, tok, keylen);

    return key;
}

int get_device_entry(const char *name, FILE *fp, Config *conf)
{
    char buf[1024];
    char *line;

    while ((line = fgets(buf, sizeof(buf), fp)) != NULL) {
        char *tabname;

        if (line[0] == '#')
            continue;

        line[strcspn(line, "\n")] = '\0';

        tabname = consume_until_whitespace(&line);

        if (tabname && !strcmp(tabname, name)) {
            conf->proto = consume_protocol(&line);
            conf->addr.sin_addr.s_addr = consume_ip_address(&line);
            conf->addr.sin_port = consume_tcp_port(&line);
            conf->key = consume_key(&line);
            conf->addr.sin_family = AF_INET;
            return 1;
        }
    }

    return 0;
}

Config get_device_conf(const char *name)
{
    Config conf;
    int opened_tabs = 0;
    int ent_found = 0;
    size_t i;

    for (i = 0; !ent_found && i < ARRAY_SIZE(g_egtabs); i++) {
        FILE *fp = fopen(g_egtabs[i], "r");

        if (fp != NULL) {
            opened_tabs++;
            ent_found = get_device_entry(name, fp, &conf);
            fclose(fp);
        }
    }

    if (opened_tabs == 0)
        fatal("Unable to open any config file");

    if (!ent_found)
        fatal("%s: unknown device", name);

    return conf;
}

int create_socket(const struct sockaddr_in *addr)
{
    int ret;
    int sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

    if (sock == -1)
        fatal("Unable to create socket: %s", strerror(errno));

    ret = connect(sock, (const struct sockaddr *)addr, sizeof(*addr));

    if (ret != 0)
        fatal("Unable to connect: %s", strerror(errno));

    return sock;
}

int wait_for_data_in_sock(int sock, struct timeval *timeout)
{
    fd_set fds;
    FD_ZERO(&fds);
    FD_SET(sock, &fds);

    return (select(sock + 1, &fds, NULL, NULL, timeout) == 1);
}

void establish_connection(int sock)
{
    int i;

    /* When the device is still on timeout from a previous session
     * it doesn't respond to the first Start condition packet. So
     * we will take several attempts. */

    for (i = 0; i < 4; i++) {
        struct timeval tv = { 0, 125000 };

        xwrite(sock, "\x11", 1);

        if (wait_for_data_in_sock(sock, &tv))
            return;
    }

    fatal("Unable to establish connection with device");
}

Session authorize(int sock, Key key)
{
    Session s;
    Res res;
    struct timeval tv = { 4, 0 };

    xread(sock, &s.task, sizeof(s.task));
    dbg4("task", s.task);

    res.loword = ((s.task[0] ^ key.octets[2]) * key.octets[0])
                 ^ (key.octets[6] | (key.octets[4] << 8))
                 ^ s.task[2];

    res.loword = htole16(res.loword);

    res.hiword = ((s.task[1] ^ key.octets[3]) * key.octets[1])
                 ^ (key.octets[7] | (key.octets[5] << 8))
                 ^ s.task[3];

    res.hiword = htole16(res.hiword);

    dbg4("res", (uint8_t *)&res);

    xwrite(sock, &res, sizeof(res));

    /* The protocol doesn't specify any explicit response on failed
     * authorization. So timeout is the only way to find out that
     * authorization hasn't been successful. */

    if (!wait_for_data_in_sock(sock, &tv))
        fatal("Authorization failed");

    s.key = key;

    return s;
}

Status decrypt_status(const uint8_t statcryp[], Session s)
{
    Status st;
    size_t i;

    for (i = 0; i < SOCKET_COUNT; i++)
        st.socket[i] =
            (((statcryp[3-i] - s.key.octets[1]) ^ s.key.octets[0]) - s.task[3])
            ^ s.task[2];

    return st;
}

uint8_t convert_v21_state(uint8_t state)
{
    switch (state) {
        case V21_STATE_ON:
            return STATE_ON;
        case V21_STATE_OFF:
            return STATE_OFF;
    }
    return STATE_INVALID;
}

Status convert_v21_status(Status st)
{
    size_t i;

    for (i = 0; i < SOCKET_COUNT; i++)
        st.socket[i] = convert_v21_state(st.socket[i]);

    return st;
}

Status recv_status(int sock, Session s, Protocol proto)
{
    Status st;
    uint8_t statcryp[STATCRYP_LEN];
    xread(sock, &statcryp, sizeof(statcryp));
    dbg4("statcryp", statcryp);
    st = decrypt_status(statcryp, s);

    /* Since the only difference between versions 2.0 and 2.1 in the
     * subset of the protocol that we use is the state constants, all
     * we need to do to support version 2.1 is just to map 2.1
     * constants to the equivalent 2.0 ones. */

    if (proto == EG_PROTO_V21)
        st = convert_v21_status(st);

    return st;
}

Action str_to_action(const char *action)
{
    if (!strcmp(action, "on"))
        return ACTION_ON;
    else if (!strcmp(action, "off"))
        return ACTION_OFF;
    else if (!strcmp(action, "toggle"))
        return ACTION_TOGGLE;
    else if (!strcmp(action, "left"))
        return ACTION_LEFT;

    return ACTION_INVALID;
}

Actions argv_to_actions(char *argv[])
{
    Actions actions;
    size_t i;

    for (i = 0; i < SOCKET_COUNT; i++) {
        Action action = str_to_action(argv[i]);

        if (action == ACTION_INVALID)
            fatal("Invalid action for socket %zu: %s", i+1, argv[i]);

        actions.socket[i] = action;
    }

    return actions;
}

uint8_t get_toggle_ctrl(uint8_t state)
{
    switch (state) {
        case STATE_ON:
        case STATE_ON_NO_VOLTAGE:
            return SWITCH_OFF;
        case STATE_OFF:
        case STATE_OFF_VOLTAGE:
            return SWITCH_ON;
    }

    return DONT_SWITCH;
}

Controls construct_controls(Status status, Actions actions)
{
    Controls ctrl;
    size_t i;

    for (i = 0; i < SOCKET_COUNT; i++) {
        switch (actions.socket[i]) {
            case ACTION_ON:
                ctrl.socket[i] = SWITCH_ON;
                break;
            case ACTION_OFF:
                ctrl.socket[i] = SWITCH_OFF;
                break;
            case ACTION_TOGGLE:
                ctrl.socket[i] = get_toggle_ctrl(status.socket[i]);
                if (ctrl.socket[i] == DONT_SWITCH)
                    warn("Cannot toggle socket %zu", i+1);
                break;
            default:
            case ACTION_LEFT:
                ctrl.socket[i] = DONT_SWITCH;
        }
    }

    return ctrl;
}

void send_controls(int sock, Session s, Controls ctrl)
{
    size_t i;
    uint8_t ctrlcryp[CTRLCRYP_LEN];

    /* Encrypt controls */
    for (i = 0; i < SOCKET_COUNT; i++)
        ctrlcryp[i] =
            (((ctrl.socket[3-i] ^ s.task[2]) + s.task[3]) ^ s.key.octets[0])
            + s.key.octets[1];

    xwrite(sock, &ctrlcryp, sizeof(ctrlcryp));
}

void close_session(int sock)
{
    /* Empirically found way to close session w/o 4 second timeout on
     * the device side is to send some invalid sequence. This helps
     * to avoid a hiccup on subsequent run of the utility. */
    xwrite(sock, "\x11", 1);
}

const char *get_state_str(uint8_t state)
{
    switch (state) {
        case STATE_ON:
            return "on";
        case STATE_ON_NO_VOLTAGE:
            return "on (no voltage!)";
        case STATE_OFF:
            return "off";
        case STATE_OFF_VOLTAGE:
            return "off (VOLTAGE IS PRESENT!)";
    }
    return "unknown";
}

void dump_status(Status st)
{
    size_t i;

    for (i = 0; i < SOCKET_COUNT; i++)
        printf("socket %zu - %s\n", i+1, get_state_str(st.socket[i]));
}

int main(int argc, char *argv[])
{
    int sock;
    Config conf;
    Session sess;

    if (argc != 2 && argc != 6) {
        fatal("egctl 0.1: EnerGenie EG-PMS-LAN control utility\n\n"
              "Usage: egctl NAME [S1 S2 S3 S4]\n"
              "  NAME is the name of the device in the egtab file\n"
              "  Sn is an action to perform on n-th socket: "
              "on, off, toggle or left");
    }

    g_egtabs[0] = get_personal_egtab_name();

    conf = get_device_conf(argv[1]);
    sock = create_socket(&conf.addr);
    establish_connection(sock);
    sess = authorize(sock, conf.key);

    if (argc == 6) {
        Actions act = argv_to_actions(argv+2);
        Status status = recv_status(sock, sess, conf.proto);
        Controls ctrl = construct_controls(status, act);
        send_controls(sock, sess, ctrl);
    }

    dump_status(recv_status(sock, sess, conf.proto));

    close_session(sock);
    close(sock);

    return EXIT_SUCCESS;
}
