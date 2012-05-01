#ifdef PALM
#include "palm/hydra-mod.h"
#else
#include "hydra-mod.h"
#endif

extern char *HYDRA_EXIT;
char *buf;

int start_cisco(int s, char *ip, int port, unsigned char options, char *miscptr, FILE * fp) {
  char *empty = "";
  char *pass, buffer[300];

  if (strlen(pass = hydra_get_next_password()) == 0)
    pass = empty;

#ifdef PALM
  sprintf(buffer, "%s\r\n", pass);
#else
  sprintf(buffer, "%.250s\r\n", pass);
#endif

  if (hydra_send(s, buffer, strlen(buffer), 0) < 0) {
    return 1;
  }
  buf = hydra_receive_line(s);
  if (strstr(buf, "assw") != NULL) {
    hydra_completed_pair();
    free(buf);
    if (memcmp(hydra_get_next_pair(), &HYDRA_EXIT, sizeof(HYDRA_EXIT)) == 0)
      return 3;
    if (strlen(pass = hydra_get_next_password()) == 0)
      pass = empty;

#ifdef PALM
    sprintf(buffer, "%s\r\n", pass);
#else
    sprintf(buffer, "%.250s\r\n", pass);
#endif

    if (hydra_send(s, buffer, strlen(buffer), 0) < 0) {
      return 1;
    }
    buf = hydra_receive_line(s);
    if (buf != NULL && strstr(buf, "assw") != NULL) {
      hydra_completed_pair();
      free(buf);
      if (memcmp(hydra_get_next_pair(), &HYDRA_EXIT, sizeof(HYDRA_EXIT)) == 0)
        return 3;
      if (strlen(pass = hydra_get_next_password()) == 0)
        pass = empty;

#ifdef PALM
      sprintf(buffer, "%s\r\n", pass);
#else
      sprintf(buffer, "%.250s\r\n", pass);
#endif

      if (hydra_send(s, buffer, strlen(buffer), 0) < 0) {
        return 1;
      }
      buf = hydra_receive_line(s);
    }

  }

  if (buf != NULL && (strstr(buf, "assw") != NULL || strstr(buf, "ad ") != NULL || strstr(buf, "attempt") != NULL || strstr(buf, "fail") != NULL)) {
    free(buf);
    hydra_completed_pair();
    if (memcmp(hydra_get_next_pair(), &HYDRA_EXIT, sizeof(HYDRA_EXIT)) == 0)
      return 3;
    return 1;
  }

  hydra_report_found_host(port, ip, "cisco", fp);
  hydra_completed_pair_found();
  if (buf != NULL)
    free(buf);
  if (memcmp(hydra_get_next_pair(), &HYDRA_EXIT, sizeof(HYDRA_EXIT)) == 0)
    return 3;
  return 1;
}

void service_cisco(char *ip, int sp, unsigned char options, char *miscptr, FILE * fp, int port) {
  int run = 1, failc = 0, retry = 1, next_run = 1, sock = -1;
  int myport = PORT_TELNET, mysslport = PORT_TELNET_SSL;

  hydra_register_socket(sp);
  if (memcmp(hydra_get_next_pair(), &HYDRA_EXIT, sizeof(HYDRA_EXIT)) == 0)
    return;
  while (1) {
    next_run = 0;
    switch (run) {
    case 1:                    /* connect and service init function */
      {
        unsigned char *buf2;
        int f = 0;

        if (sock >= 0)
          sock = hydra_disconnect(sock);
//        usleep(275000);
        if ((options & OPTION_SSL) == 0) {
          if (port != 0)
            myport = port;
          sock = hydra_connect_tcp(ip, myport);
          port = myport;
        } else {
          if (port != 0)
            mysslport = port;
          sock = hydra_connect_ssl(ip, mysslport);
          port = mysslport;
        }
        if (sock < 0) {
          hydra_report(stderr, "Error: Child with pid %d terminating, can not connect\n", (int) getpid());
          hydra_child_exit(1);
        }
        do {
          if (f != 0)
            free(buf2);
          else
            f = 1;
          if ((buf2 = (unsigned char *) hydra_receive_line(sock)) == NULL) {
            if (failc < retry) {
              next_run = 1;
              failc++;
              hydra_report(stderr, "Error: Child with pid %d was disconnected - retrying (%d of %d retries)\n", (int) getpid(), failc, retry);
              sleep(3);
              break;
            } else {
              hydra_report(stderr, "Error: Child with pid %d was disconnected - exiting\n", (int) getpid());
              hydra_child_exit(0);
            }
          }
        } while (strstr((char *) buf2, "assw") == NULL);
        free(buf2);
        if (next_run != 0)
          break;
        failc = 0;
        next_run = 2;
        break;
      }
    case 2:                    /* run the cracking function */
      next_run = start_cisco(sock, ip, port, options, miscptr, fp);
      break;
    case 3:                    /* clean exit */
      if (sock >= 0)
        sock = hydra_disconnect(sock);
      hydra_child_exit(0);
      return;
    default:
      hydra_report(stderr, "Caught unknown return code, exiting!\n");
      hydra_child_exit(0);
#ifdef PALM
      return;
#else
      hydra_child_exit(2);
#endif
    }
    run = next_run;
  }
}
