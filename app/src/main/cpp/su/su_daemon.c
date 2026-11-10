#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <termios.h>
#include <unistd.h>

#define SOCK_PATH "/data/local/tmp/.oplus_su.sock"
#define CMD_PATH  "/data/local/tmp/oplus_su_cmd.sh"
#define OUT_PATH  "/data/local/tmp/oplus_su_out.txt"
#define LOG_PATH  "/data/local/tmp/oplus_su.log"

static uid_t allowed_app_uid = (uid_t)-1;

static void set_root_env(void) {
  setenv("PATH",
         "/product/bin:/apex/com.android.runtime/bin:/apex/com.android.art/bin:"
         "/system_ext/bin:/system/bin:/system/xbin:/odm/bin:/vendor/bin:"
         "/vendor/xbin:/data/local/tmp",
         1);
  setenv("HOME", "/data/local/tmp", 1);
  setenv("USER", "root", 1);
  setenv("LOGNAME", "root", 1);
}

static void xwrite(int fd, const void *buf, size_t len) {
  const char *p = (const char *)buf;
  while (len) {
    ssize_t n = write(fd, p, len);
    if (n < 0 && errno == EINTR) continue;
    if (n <= 0) _exit(111);
    p += n;
    len -= (size_t)n;
  }
}

static int read_full(int fd, void *buf, size_t len) {
  char *p = (char *)buf;
  while (len) {
    ssize_t n = read(fd, p, len);
    if (n < 0 && errno == EINTR) continue;
    if (n <= 0) return 0;
    p += n;
    len -= (size_t)n;
  }
  return 1;
}

static int connect_daemon(void) {
  int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
  if (fd < 0) {
    perror("su: socket");
    return -1;
  }
  struct sockaddr_un sun;
  memset(&sun, 0, sizeof(sun));
  sun.sun_family = AF_UNIX;
  snprintf(sun.sun_path, sizeof(sun.sun_path), "%s", SOCK_PATH);
  if (connect(fd, (struct sockaddr *)&sun, sizeof(sun)) != 0) {
    close(fd);
    return -1;
  }
  return fd;
}

static int pump_pair(int a, int b) {
  char buf[4096];
  int a_open = 1, b_open = 1;
  while (a_open || b_open) {
    struct pollfd pfd[2];
    int nfd = 0;
    if (a_open) { pfd[nfd].fd = a; pfd[nfd].events = POLLIN; nfd++; }
    if (b_open) { pfd[nfd].fd = b; pfd[nfd].events = POLLIN; nfd++; }
    int pr = poll(pfd, (nfds_t)nfd, -1);
    if (pr < 0 && errno == EINTR) continue;
    if (pr < 0) return 1;
    int idx = 0;
    if (a_open) {
      short re = pfd[idx++].revents;
      if (re & POLLIN) {
        ssize_t n = read(a, buf, sizeof(buf));
        if (n > 0) xwrite(b, buf, (size_t)n);
        else { a_open = 0; shutdown(b, SHUT_WR); }
      } else if (re & (POLLHUP | POLLERR | POLLNVAL)) { a_open = 0; shutdown(b, SHUT_WR); }
    }
    if (b_open) {
      short re = pfd[idx++].revents;
      if (re & POLLIN) {
        ssize_t n = read(b, buf, sizeof(buf));
        if (n > 0) xwrite(a, buf, (size_t)n);
        else { b_open = 0; shutdown(a, SHUT_WR); }
      } else if (re & (POLLHUP | POLLERR | POLLNVAL)) { b_open = 0; shutdown(a, SHUT_WR); }
    }
  }
  return 0;
}

/* pump_pair() cannot be used client-side: it writes whatever the daemon sends
 * back to its first fd, which for a client is STDIN_FILENO. On a real terminal
 * fd 0 happens to be O_RDWR so that works, but with stdin redirected from a
 * pipe or file the write fails and xwrite() _exit(111)s, losing all output. */
static int pump_client(int fd) {
  char buf[4096];
  int in_open = 1, out_open = 1;
  while (in_open || out_open) {
    struct pollfd pfd[2];
    int nfd = 0;
    if (in_open) { pfd[nfd].fd = STDIN_FILENO; pfd[nfd].events = POLLIN; nfd++; }
    if (out_open) { pfd[nfd].fd = fd; pfd[nfd].events = POLLIN; nfd++; }
    int pr = poll(pfd, (nfds_t)nfd, -1);
    if (pr < 0 && errno == EINTR) continue;
    if (pr < 0) return 1;
    int idx = 0;
    if (in_open) {
      short re = pfd[idx++].revents;
      if (re & POLLIN) {
        ssize_t n = read(STDIN_FILENO, buf, sizeof(buf));
        if (n > 0) xwrite(fd, buf, (size_t)n);
        else { in_open = 0; shutdown(fd, SHUT_WR); }
      } else if (re & (POLLHUP | POLLERR | POLLNVAL)) { in_open = 0; shutdown(fd, SHUT_WR); }
    }
    if (out_open) {
      short re = pfd[idx++].revents;
      if (re & POLLIN) {
        ssize_t n = read(fd, buf, sizeof(buf));
        if (n > 0) xwrite(STDOUT_FILENO, buf, (size_t)n);
        else out_open = 0;
      } else if (re & (POLLHUP | POLLERR | POLLNVAL)) out_open = 0;
    }
  }
  return 0;
}

static int client_main(int argc, char **argv) {
  int fd = connect_daemon();
  if (fd < 0) {
    fprintf(stderr, "su: no daemon at %s\n", SOCK_PATH);
    return 127;
  }

  if (argc >= 3 && strcmp(argv[1], "-c") == 0) {
    char mode = 'C';
    uint32_t len = (uint32_t)strlen(argv[2]);
    xwrite(fd, &mode, 1);
    xwrite(fd, &len, sizeof(len));
    xwrite(fd, argv[2], len);
    shutdown(fd, SHUT_WR);
    char buf[4096];
    for (;;) {
      ssize_t n = read(fd, buf, sizeof(buf));
      if (n < 0 && errno == EINTR) continue;
      if (n <= 0) break;
      xwrite(STDOUT_FILENO, buf, (size_t)n);
    }
    close(fd);
    return 0;
  }

  if (argc >= 2 && strcmp(argv[1], "--status") == 0) {
    char mode = 'S';
    xwrite(fd, &mode, 1);
    shutdown(fd, SHUT_WR);
    char buf[512];
    ssize_t n = read(fd, buf, sizeof(buf) - 1);
    if (n > 0) { buf[n] = 0; fputs(buf, stdout); }
    close(fd);
    return 0;
  }

  char mode = 'I';
  xwrite(fd, &mode, 1);

  /* The remote side runs sh -i on its own pty, so the local terminal has to
   * stop doing line editing and echoing or every keystroke shows twice. */
  struct termios saved;
  int raw = isatty(STDIN_FILENO) && tcgetattr(STDIN_FILENO, &saved) == 0;
  if (raw) {
    struct termios rawmode = saved;
    cfmakeraw(&rawmode);
    tcsetattr(STDIN_FILENO, TCSANOW, &rawmode);
  }
  int rc = pump_client(fd);
  if (raw) tcsetattr(STDIN_FILENO, TCSANOW, &saved);
  close(fd);
  return rc;
}

static void exec_command_client(int conn, const char *cmd) {
  pid_t pid = fork();
  if (pid == 0) {
    dup2(conn, STDIN_FILENO);
    dup2(conn, STDOUT_FILENO);
    dup2(conn, STDERR_FILENO);
    if (conn > STDERR_FILENO) close(conn);
    /* The cred swap leaves init_cred.gid clobbered globally (the erase's
     * relink store writes TARGET into VALUE+8). This fork's PRIVATE cred
     * copy can be repaired: setresgid/setresuid rewrite the child's own
     * gid/uid, so exec survives. Do NOT call setgroups here -- walking the
     * stale group_info of the swapped cred hangs. */
    /* setresgid kills: cred writes already made us uid 0 */
    /* setresuid kills: collateral-corrupted init_cred */
    set_root_env();
    execl("/system/bin/sh", "sh", "-c", cmd, (char *)NULL);
    _exit(127);
  }
  int status = 0;
  while (waitpid(pid, &status, 0) < 0 && errno == EINTR) {}
}

static int open_pty_master(char *slave, size_t slave_len) {
  int master = posix_openpt(O_RDWR | O_NOCTTY | O_CLOEXEC);
  if (master < 0) return -1;
  if (grantpt(master) != 0 || unlockpt(master) != 0) { close(master); return -1; }
  if (ptsname_r(master, slave, slave_len) != 0) { close(master); return -1; }
  return master;
}

static void exec_interactive_client(int conn) {
  char slave_name[128];
  int master = open_pty_master(slave_name, sizeof(slave_name));
  if (master < 0) {
    const char msg[] = "su daemon: failed to open pty\n";
    xwrite(conn, msg, sizeof(msg) - 1);
    return;
  }
  pid_t pid = fork();
  if (pid == 0) {
    setsid();
    /* setresgid kills: cred writes already made us uid 0 */
    /* setresuid kills: collateral-corrupted init_cred */
    int slave = open(slave_name, O_RDWR | O_NOCTTY);
    if (slave < 0) _exit(126);
    ioctl(slave, TIOCSCTTY, 0);
    dup2(slave, STDIN_FILENO);
    dup2(slave, STDOUT_FILENO);
    dup2(slave, STDERR_FILENO);
    if (slave > STDERR_FILENO) close(slave);
    close(master);
    close(conn);
    set_root_env();
    execl("/system/bin/sh", "sh", "-i", (char *)NULL);
    _exit(127);
  }
  pump_pair(conn, master);
  kill(pid, SIGHUP);
  int status = 0;
  while (waitpid(pid, &status, 0) < 0 && errno == EINTR) {}
  close(master);
}

static void serve_one(int conn) {
  struct ucred peer;
  socklen_t peer_len = sizeof(peer);
  if (getsockopt(conn, SOL_SOCKET, SO_PEERCRED, &peer, &peer_len) != 0 ||
      peer_len != sizeof(peer) ||
      (peer.uid != 0 && peer.uid != 2000 && peer.uid != allowed_app_uid)) {
    const char denied[] = "su: permission denied\n";
    (void)write(conn, denied, sizeof(denied) - 1);
    return;
  }
  char mode = 0;
  if (!read_full(conn, &mode, 1)) return;

  if (mode == 'C') {
    uint32_t len = 0;
    if (!read_full(conn, &len, sizeof(len)) || len > 65536) return;
    char *cmd = (char*)calloc(1, (size_t)len + 1);
    if (!cmd) return;
    if (!read_full(conn, cmd, len)) { free(cmd); return; }
    exec_command_client(conn, cmd);
    free(cmd);
  } else if (mode == 'I') {
    exec_interactive_client(conn);
  } else if (mode == 'S') {
    char buf[256];
    /* Each accepted client is handled by a short-lived fork child.  Report
     * the long-lived daemon parent PID, not this per-query worker PID, so the
     * UI status does not appear to change on every poll. */
    int n = snprintf(buf, sizeof(buf), "pid=%d uid=%d euid=%d gid=%d\n",
                     getppid(), getuid(), geteuid(), getgid());
    if (n > 0) xwrite(conn, buf, (size_t)n);
  }
}

/*
 * File mailbox, so root is reachable from adb shell with no client binary and
 * no socket permission at all. Delivery has to be an atomic rename into
 * CMD_PATH (write a temp file in the same directory, then mv) or the poller can
 * read a half-written command.
 */
static void *file_channel(void *unused) {
  (void)unused;
  char cmd[8192];
  for (;;) {
    usleep(250000);
    int fd = open(CMD_PATH, O_RDONLY | O_CLOEXEC);
    if (fd < 0) continue;
    ssize_t n = read(fd, cmd, sizeof(cmd) - 1);
    close(fd);
    if (n <= 0) continue;
    cmd[n] = 0;
    /* Consume before running: a long command must not be re-executed. */
    truncate(CMD_PATH, 0);

    int out = open(OUT_PATH, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0666);
    pid_t pid = fork();
    if (pid == 0) {
      if (out >= 0) {
        dup2(out, STDOUT_FILENO);
        dup2(out, STDERR_FILENO);
        close(out);
      }
      /* setresgid kills: cred writes already made us uid 0 */
      /* setresuid kills: collateral-corrupted init_cred */
      set_root_env();
      execl("/system/bin/sh", "sh", "-c", cmd, (char *)NULL);
      _exit(127);
    }
    int status = 0;
    if (pid > 0) while (waitpid(pid, &status, 0) < 0 && errno == EINTR) {}
    if (out >= 0) {
      char tail[128];
      int tn = snprintf(tail, sizeof(tail), "\n[rc=%d]\n",
                        WIFEXITED(status) ? WEXITSTATUS(status) : -1);
      if (tn > 0) xwrite(out, tail, (size_t)tn);
      close(out);
    }
    chmod(OUT_PATH, 0666);
  }
  return NULL;
}

int daemon_main(void) {
  signal(SIGPIPE, SIG_IGN);
  signal(SIGHUP, SIG_IGN);
  /* Payload preload.c run_su_daemon_direct model: when exec is blocked by
   * seccomp, the daemon logic runs in-process (no execl of an external
   * binary). The daemon itself only does socket + fork + execv at command
   * time, and those children inherit our patched (no-seccomp) state. */
  /* Do NOT call setresgid/setresuid here: on a cred that still points at
   * the corrupted init_cred these syscalls kill the task (measured: daemon
   * died before socket creation). The daemon itself never execs anything;
   * only its per-command children do, and those already repair their own
   * credentials in exec_command_client. */
  set_root_env();
  setsid();
  const char *app_uid = getenv("OPLUS_SU_APP_UID");
  if (app_uid && *app_uid) {
    char *end = NULL;
    unsigned long parsed = strtoul(app_uid, &end, 10);
    if (end && *end == '\0' && parsed <= UINT32_MAX)
      allowed_app_uid = (uid_t)parsed;
  }

  int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
  if (fd < 0) return 1;

  unlink(SOCK_PATH);
  struct sockaddr_un sun;
  memset(&sun, 0, sizeof(sun));
  sun.sun_family = AF_UNIX;
  snprintf(sun.sun_path, sizeof(sun.sun_path), "%s", SOCK_PATH);
  if (bind(fd, (struct sockaddr *)&sun, sizeof(sun)) != 0) return 1;
  chmod(SOCK_PATH, 0777);
  if (listen(fd, 32) != 0) return 1;

  unlink(CMD_PATH);
  unlink(OUT_PATH);
  int cf = open(CMD_PATH, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0666);
  if (cf >= 0) close(cf);

  pthread_t th;
  pthread_create(&th, NULL, file_channel, NULL);
  pthread_detach(th);

  int lf = open(LOG_PATH, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0666);
  if (lf >= 0) {
    char b[192];
    int n = snprintf(b, sizeof(b), "su daemon ready pid=%d uid=%d euid=%d gid=%d sock=%s\n",
                     getpid(), getuid(), geteuid(), getgid(), SOCK_PATH);
    if (n > 0) xwrite(lf, b, (size_t)n);
    close(lf);
  }

  for (;;) {
    int conn = accept4(fd, NULL, NULL, SOCK_CLOEXEC);
    if (conn < 0 && errno == EINTR) continue;
    if (conn < 0) { sleep(1); continue; }
    pid_t pid = fork();
    if (pid == 0) {
      close(fd);
      serve_one(conn);
      close(conn);
      _exit(0);
    }
    close(conn);
    while (waitpid(-1, NULL, WNOHANG) > 0) {}
  }
}

int su_main(int argc, char **argv) {
  if (argc >= 2 && strcmp(argv[1], "--daemon") == 0) return daemon_main();
  return client_main(argc, argv);
}

/* In-process daemon entry (Payload preload.c run_su_daemon_direct model).
 * Called from root_stage.cpp start_daemon() when execl fails - the daemon
 * logic runs in THIS process image with THIS credential (uid=0), no exec. */
int su_daemon_inproc(void) {
  return daemon_main();
}
