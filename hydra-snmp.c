#include "hydra-mod.h"

extern int hydra_data_ready_timed(int socket, long sec, long usec);

extern char *HYDRA_EXIT;
char *buf;
int snmpversion;
int snmpread;

int start_snmp(int s, char *ip, int port, unsigned char options, char *miscptr, FILE * fp) {
  char *empty = "\"\"";
  char *login, *pass, buffer[1024];
  int i, j, size;
  char buf[1024];
  extern int snmpversion;
  extern int snmpread;

  struct SNMPV1_A {
    char ID;
    char len;
    char ver[3];
    char comid;
    char comlen;
  };

  struct SNMPV1_A snmpv1_a = {
    .ID = '\x30',
    .len = '\x00',
    .ver = "\x02\x01\x00",      /* \x02\x01\x01 for snmp v2c */
    .comid = '\x04',
    .comlen = '\x00'
  };

  struct SNMPV1_R {
    char type[2];
    char identid[2];
    char ident[4];
    char errstat[3];
    char errind[3];
    char objectid[2];
    char object[11];
    char value[3];
  } snmpv1_r = {
    .type = "\xa0\x1b",         /* GET */
      .identid = "\x02\x04",.ident = "\x1a\x5e\x97\x00",        /* random crap :) */
      .errstat = "\x02\x01\x00",        /* no error */
      .errind = "\x02\x01\x00", /* error index 0 */
      .objectid = "\x30\x0d",.object = "\x30\x0b\x06\x07\x2b\x06\x01\x02\x01\x01\x01",  /* sysDescr */
      .value = "\x05\x00"       /* we just read, so value = 0 */
  };

  struct SNMPV1_W {
    char type[2];
    char identid[2];
    char ident[4];
    char errstat[3];
    char errind[3];
    char objectid[2];
    char object[12];
    char value[8];
  } snmpv1_w = {
    .type = "\xa3\x21",         /* SET */
      .identid = "\x02\x04",.ident = "\x1a\x5e\x97\x22",        /* random crap :) */
      .errstat = "\x02\x01\x00",        /* no error */
      .errind = "\x02\x01\x00", /* error index 0 */
      .objectid = "\x30\x13",   /* string */
      .object = "\x30\x11\x06\x08\x2b\x06\x01\x02\x01\x01\x05\x00",.value = "\x04\x05HYDRA"     /* we just read, so value = 0 */
  };

  /* do we attack snmp v1 or v2c? */
  if (snmpversion) {
    snmpv1_a.ver[2] = '\x01';
  }

  if (snmpread) {
    size = sizeof(snmpv1_r);

/*    hydra_report(stdout, "[DATA] Guessing for SNMP READ access\n"); */
  } else {
    size = sizeof(snmpv1_w);

/*    hydra_report(stdout, "[DATA] Guessing for SNMP WRITE access\n"); */
  }

  if (strlen(login = hydra_get_next_login()) == 0)
    login = empty;
  if (strlen(pass = hydra_get_next_password()) == 0)
    pass = empty;

  snmpv1_a.comlen = (char) strlen(pass);
  snmpv1_a.len = snmpv1_a.comlen + size + sizeof(snmpv1_a) - 3;

  i = sizeof(snmpv1_a);
  memcpy(buffer, &snmpv1_a, i);
  strcpy(buffer + i, pass);
  i += strlen(pass);

  if (snmpread) {
    memcpy(buffer + i, &snmpv1_r, size);
    i += sizeof(snmpv1_r);
  } else {
    memcpy(buffer + i, &snmpv1_w, size);
    i += sizeof(snmpv1_w);
  }

  if (hydra_send(s, buffer, i - 1, 0) < 0) {
    return 3;
  }
  hydra_send(s, buffer, i - 1, 0);
  hydra_send(s, buffer, i - 1, 0);

  if (hydra_data_ready_timed(s, 5, 0) > 0) {
    i = hydra_recv(s, (char *) buf, sizeof(buf));

    /* stolen from ADMsnmp... :P */
    for (j = 0; j < i; j++) {
      if (buf[j] == '\x04') {   /* community name */
        for (j = j + buf[j + 1]; j + 2 < i; j++) {
          if (buf[j] == '\xa2') {       /* PDU Response */
            for (; j + 2 < i; j++) {
              if (buf[j] == '\x02') {   /* ID */
                for (j = j + (buf[j + 1]); j + 2 < i; j++) {
                  if (buf[j] == '\x02') {
                    if (buf[j + 1] == '\x01') { /* good ! */
                      hydra_report_found_host(port, ip, "snmp", fp);
                      hydra_completed_pair_found();
                    }
                    hydra_completed_pair();
                    if (memcmp(hydra_get_next_pair(), &HYDRA_EXIT, sizeof(HYDRA_EXIT)) == 0)
                      return 3;

                    return 1;
                  }
                }
              }
            }
          }
        }
      }
    }
  }

  hydra_completed_pair();
  if (memcmp(hydra_get_next_pair(), &HYDRA_EXIT, sizeof(HYDRA_EXIT)) == 0)
    return 3;

  return 1;
}

void service_snmp(char *ip, int sp, unsigned char options, char *miscptr, FILE * fp, int port) {
  int run = 1, next_run = 1, sock = -1;
  int myport = PORT_SNMP;
  extern int snmpversion;
  extern int snmpread;

  if ((miscptr != NULL) && (strchr(miscptr, '2'))) {
    snmpversion = 1;
  } else {
    snmpversion = 0;
  }

  if ((miscptr != NULL) && (strchr(miscptr, 'w'))) {
    snmpread = 0;
  } else {
    snmpread = 1;
  }

  hydra_register_socket(sp);

  if (memcmp(hydra_get_next_pair(), &HYDRA_EXIT, sizeof(HYDRA_EXIT)) == 0)
    run = 3;

  while (1) {
    switch (run) {
    case 1:                    /* connect and service init function */
//      if (sock >= 0)
//      sock = hydra_disconnect(sock);
//      usleep(300000);
      if (sock < 0) {
        if (port != 0)
          myport = port;
        sock = hydra_connect_udp(ip, myport);
        port = myport;
        if (sock < 0) {
          hydra_report(stderr, "Error: Child with pid %d terminating, can not connect\n", (int) getpid());
          hydra_child_exit(1);
        }
      }
      next_run = start_snmp(sock, ip, port, options, miscptr, fp);
      break;
    case 3:                    /* clean exit */
      if (sock >= 0)
        sock = hydra_disconnect(sock);
      hydra_child_exit(2);
      return;
    default:
      hydra_report(stderr, "Caught unknown return code, exiting!\n");
      hydra_child_exit(2);
    }
    run = next_run;
  }
}
