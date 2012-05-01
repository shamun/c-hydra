#include "hydra-mod.h"
#include "sasl.h"

//openssl s_client -starttls pop3 -crlf -connect 192.168.0.10:110

extern int module_auth_type;
extern char *HYDRA_EXIT;
char *buf;

int pop3_auth_mechanism = AUTH_CLEAR;
char apop_challenge[300] = "";

char *pop3_read_server_capacity(int sock) {
  char *ptr = NULL;
  int resp = 0;
  char *buf = NULL;

  do {
    if (buf != NULL)
      free(buf);
    ptr = buf = hydra_receive_line(sock);
    if (buf != NULL) {
      if (strstr(buf, "SASL") != NULL && buf[0] == '+') {
        resp = 1;
        /* we got the capability info then get the completed warning info from server */
        while (hydra_data_ready(sock)) {
          free(buf);
          buf = hydra_receive_line(sock);
        }
      } else {
        if (buf[strlen(buf) - 1] == '\n')
          buf[strlen(buf) - 1] = 0;
        if (buf[strlen(buf) - 1] == '\r')
          buf[strlen(buf) - 1] = 0;
        if (*(ptr) == '.' || *(ptr) == '-')
          resp = 1;
      }
    }
  } while (buf != NULL && resp == 0);
  return buf;
}

int start_pop3(int s, char *ip, int port, unsigned char options, char *miscptr, FILE * fp) {
  char *empty = "\"\"";
  char *login, *pass, buffer[500], buffer2[500];

  if (strlen(login = hydra_get_next_login()) == 0)
    login = empty;
  if (strlen(pass = hydra_get_next_password()) == 0)
    pass = empty;

  while (hydra_data_ready(s) > 0) {
    if ((buf = hydra_receive_line(s)) == NULL)
      return (1);
    free(buf);
  }

  switch (pop3_auth_mechanism) {
#ifdef LIBOPENSSLNEW
  case AUTH_APOP:{
      MD5_CTX c;
      unsigned char md5_raw[MD5_DIGEST_LENGTH];

      MD5_Init(&c);
      MD5_Update(&c, apop_challenge, strlen(apop_challenge));
      MD5_Update(&c, pass, strlen(pass));
      MD5_Final(md5_raw, &c);

      int i;
      char *pbuffer = buffer2;

      for (i = 0; i < MD5_DIGEST_LENGTH; i++) {
        sprintf(pbuffer, "%02x", md5_raw[i]);
        pbuffer += 2;
      }
      sprintf(buffer, "APOP %s %s\r\n", login, buffer2);
    }
    break;
#endif

  case AUTH_LOGIN:{
      sprintf(buffer, "AUTH LOGIN\r\n");
      if (hydra_send(s, buffer, strlen(buffer), 0) < 0) {
        return 1;
      }
      if ((buf = hydra_receive_line(s)) == NULL)
        return 1;
      if (buf[0] != '+') {
        hydra_report(stderr, "[ERROR] POP3 LOGIN AUTH : %s\n", buf);
        free(buf);
        return 3;
      }
      free(buf);
      strcpy(buffer2, login);
      hydra_tobase64((unsigned char *) buffer2, strlen(buffer2), sizeof(buffer2));

      sprintf(buffer, "%.250s\r\n", buffer2);
      if (hydra_send(s, buffer, strlen(buffer), 0) < 0) {
        return 1;
      }
      if ((buf = hydra_receive_line(s)) == NULL)
        return 1;
      if (buf[0] != '+') {
        hydra_report(stderr, "[ERROR] POP3 LOGIN AUTH : %s\n", buf);
        free(buf);
        return 3;
      }
      free(buf);
      strcpy(buffer2, pass);
      hydra_tobase64((unsigned char *) buffer2, strlen(buffer2), sizeof(buffer2));
      sprintf(buffer, "%.250s\r\n", buffer2);
    }
    break;

  case AUTH_PLAIN:{
      sprintf(buffer, "AUTH PLAIN\r\n");
      if (hydra_send(s, buffer, strlen(buffer), 0) < 0) {
        return 1;
      }
      if ((buf = hydra_receive_line(s)) == NULL)
        return 1;
      if (buf[0] != '+') {
        hydra_report(stderr, "[ERROR] POP3 PLAIN AUTH : %s\n", buf);
        free(buf);
        return 3;
      }
      free(buf);

      memset(buffer, 0, sizeof(buffer));
      sasl_plain(buffer, login, pass);
      sprintf(buffer, "%.250s\r\n", buffer);
    }
    break;

#ifdef LIBOPENSSLNEW
  case AUTH_CRAMMD5:
  case AUTH_CRAMSHA1:
  case AUTH_CRAMSHA256:{
      int rc = 0;
      char *preplogin;

      rc = sasl_saslprep(login, SASL_ALLOW_UNASSIGNED, &preplogin);
      if (rc) {
        return 3;
      }

      switch (pop3_auth_mechanism) {
      case AUTH_CRAMMD5:
        sprintf(buffer, "AUTH CRAM-MD5\r\n");
        break;
      case AUTH_CRAMSHA1:
        sprintf(buffer, "AUTH CRAM-SHA1\r\n");
        break;
      case AUTH_CRAMSHA256:
        sprintf(buffer, "AUTH CRAM-SHA256\r\n");
        break;
      }
      if (hydra_send(s, buffer, strlen(buffer), 0) < 0) {
        return 1;
      }
      //get the one-time BASE64 encoded challenge
      if ((buf = hydra_receive_line(s)) == NULL)
        return 1;
      if (buf[0] != '+') {
        switch (pop3_auth_mechanism) {
        case AUTH_CRAMMD5:
          hydra_report(stderr, "[ERROR] POP3 CRAM-MD5 AUTH : %s\n", buf);
          break;
        case AUTH_CRAMSHA1:
          hydra_report(stderr, "[ERROR] POP3 CRAM-SHA1 AUTH : %s\n", buf);
          break;
        case AUTH_CRAMSHA256:
          hydra_report(stderr, "[ERROR] POP3 CRAM-SHA256 AUTH : %s\n", buf);
          break;
        }
        free(buf);
        return 3;
      }

      memset(buffer, 0, sizeof(buffer));
      from64tobits((char *) buffer, buf + 2);
      free(buf);

      memset(buffer2, 0, sizeof(buffer2));

      switch (pop3_auth_mechanism) {
      case AUTH_CRAMMD5:{
          sasl_cram_md5(buffer2, pass, buffer);
          sprintf(buffer, "%s %.250s", preplogin, buffer2);
        }
        break;
      case AUTH_CRAMSHA1:{
          sasl_cram_sha1(buffer2, pass, buffer);
          sprintf(buffer, "%s %.250s", preplogin, buffer2);
        }
        break;
      case AUTH_CRAMSHA256:{
          sasl_cram_sha256(buffer2, pass, buffer);
          sprintf(buffer, "%s %.250s", preplogin, buffer2);
        }
        break;
      }
      hydra_tobase64((unsigned char *) buffer, strlen(buffer), sizeof(buffer));
      sprintf(buffer, "%.250s\r\n", buffer);
      free(preplogin);
    }
    break;

  case AUTH_DIGESTMD5:{
      sprintf(buffer, "AUTH DIGEST-MD5\r\n");

      if (hydra_send(s, buffer, strlen(buffer), 0) < 0)
        return 1;
      //receive
      if ((buf = hydra_receive_line(s)) == NULL)
        return 1;
      if (buf[0] != '+') {
        hydra_report(stderr, "[ERROR] POP3 DIGEST-MD5 AUTH : %s\n", buf);
        free(buf);
        return 3;
      }
      memset(buffer, 0, sizeof(buffer));
      from64tobits((char *) buffer, buf);
      free(buf);

      if (verbose)
        hydra_report(stderr, "[VERBOSE] S: %s\n", buffer);

      sasl_digest_md5(buffer2, login, pass, buffer, miscptr, "pop", NULL, 0, NULL);
      if (buffer2 == NULL)
        return 3;

      if (verbose)
        hydra_report(stderr, "[VERBOSE] C: %s\n", buffer2);
      hydra_tobase64((unsigned char *) buffer2, strlen(buffer2), sizeof(buffer2));
      sprintf(buffer, "%s\r\n", buffer2);
    }
    break;
#endif

  case AUTH_NTLM:{
      unsigned char buf1[4096];
      unsigned char buf2[4096];

      //Send auth request
      sprintf(buffer, "AUTH NTLM\r\n");

      if (hydra_send(s, buffer, strlen(buffer), 0) < 0)
        return 1;
      //receive
      if ((buf = hydra_receive_line(s)) == NULL)
        return 1;
      if (buf[0] != '+') {
        hydra_report(stderr, "[ERROR] POP3 NTLM AUTH : %s\n", buf);
        free(buf);
        return 3;
      }
      free(buf);
      //send auth and receive challenge
      //send auth request: lst the server send it's own hostname and domainname
      buildAuthRequest((tSmbNtlmAuthRequest *) buf2, 0, NULL, NULL);
      to64frombits(buf1, buf2, SmbLength((tSmbNtlmAuthRequest *) buf2));

      sprintf(buffer, "%s\r\n", buf1);
      if (hydra_send(s, buffer, strlen(buffer), 0) < 0)
        return 1;
      if ((buf = hydra_receive_line(s)) == NULL)
        return (1);

      //recover challenge
      from64tobits((char *) buf1, buf + 2);
      free(buf);

      //Send response
      buildAuthResponse((tSmbNtlmAuthChallenge *) buf1, (tSmbNtlmAuthResponse *) buf2, 0, login, pass, NULL, NULL);
      to64frombits(buf1, buf2, SmbLength((tSmbNtlmAuthResponse *) buf2));

      sprintf(buffer, "%s\r\n", buf1);
    }
    break;
  default:
    sprintf(buffer, "USER %.250s\r\n", login);
    if (hydra_send(s, buffer, strlen(buffer), 0) < 0) {
      return 1;
    }
    if ((buf = hydra_receive_line(s)) == NULL)
      return (1);
    if (buf[0] != '+') {
      hydra_report(stderr, "[ERROR] POP3 protocol or service shutdown: %s\n", buf);
      free(buf);
      return (3);
    }
    free(buf);
    sprintf(buffer, "PASS %.250s\r\n", pass);
  }

  if (hydra_send(s, buffer, strlen(buffer), 0) < 0) {
    return 1;
  }
  if ((buf = hydra_receive_line(s)) == NULL)
    return (1);

  if (buf[0] == '+') {
    hydra_report_found_host(port, ip, "pop3", fp);
    hydra_completed_pair_found();
    free(buf);
    if (memcmp(hydra_get_next_pair(), &HYDRA_EXIT, sizeof(HYDRA_EXIT)) == 0)
      return 3;
    return 1;
  }
  /* special AS/400 hack */
  if (strstr(buf, "CPF2204") != NULL || strstr(buf, "CPF22E3") != NULL || strstr(buf, "CPF22E4") != NULL || strstr(buf, "CPF22E5") != NULL) {
    hydra_completed_pair_skip();
    free(buf);
    if (memcmp(hydra_get_next_pair(), &HYDRA_EXIT, sizeof(HYDRA_EXIT)) == 0)
      return 3;
    return 1;
  }
  free(buf);
  hydra_completed_pair();
  if (memcmp(hydra_get_next_pair(), &HYDRA_EXIT, sizeof(HYDRA_EXIT)) == 0)
    return 3;

  return 2;
}

void service_pop3(char *ip, int sp, unsigned char options, char *miscptr, FILE * fp, int port) {
  int run = 1, next_run = 1, sock = -1;
  int myport = PORT_POP3, mysslport = PORT_POP3_SSL, disable_tls = 0;
  char *ptr = NULL;
  char *buffer1 = "CAPA\r\n";

  hydra_register_socket(sp);
  if (memcmp(hydra_get_next_pair(), &HYDRA_EXIT, sizeof(HYDRA_EXIT)) == 0)
    return;
  while (1) {
    switch (run) {
    case 1:                    /* connect and service init function */
      if (sock >= 0)
        sock = hydra_disconnect(sock);
//      usleep(300000);
      if ((options & OPTION_SSL) == 0) {
        if (port != 0)
          myport = port;
        sock = hydra_connect_tcp(ip, myport);
        port = myport;
      } else {
        if (port != 0)
          mysslport = port;
        sock = hydra_connect_ssl(ip, mysslport);
        port = myport;
      }
      if (sock < 0) {
        hydra_report(stderr, "[ERROR] Child with pid %d terminating, can not connect\n", (int) getpid());
        hydra_child_exit(1);
      }
      buf = hydra_receive_line(sock);
      if (buf == NULL || buf[0] != '+') {       /* check the first line */
        if (verbose || debug) hydra_report(stderr, "[ERROR] Not an POP3 protocol or service shutdown: %s\n", buf);
        hydra_child_exit(2);
      }

      ptr = strstr(buf, "<");
      if (ptr != NULL && buf[0] == '+') {
        if (ptr[strlen(ptr) - 1] == '\n')
          ptr[strlen(ptr) - 1] = 0;
        if (ptr[strlen(ptr) - 1] == '\r')
          ptr[strlen(ptr) - 1] = 0;
        strcpy(apop_challenge, ptr);
      }
      free(buf);

      /* send capability request */
      if (hydra_send(sock, buffer1, strlen(buffer1), 0) < 0)
        hydra_child_exit(2);

      buf = pop3_read_server_capacity(sock);

      if (buf == NULL) {
        hydra_child_exit(2);
      }
#ifdef LIBOPENSSLNEW
      if (!disable_tls) {
	/* check for STARTTLS, if available we may have access to more basic auth methods */
	if (strstr(buf, "STLS") != NULL) {
          hydra_send(sock, "STLS\r\n", strlen("STLS\r\n"), 0);
          free(buf);
          buf = hydra_receive_line(sock);
          if (buf[0] != '+') {
            if (verbose)
              hydra_report(stderr, "[VERBOSE] TLS negotiation failed\n");
          } else {
            free(buf);
            if ((hydra_connect_to_ssl(sock) == -1)) {
              if (verbose)
        	hydra_report(stderr, "[ERROR] Can't use TLS\n");
              disable_tls = 1;
              run = 1;
              break;
            } else {
              if (verbose)
        	hydra_report(stderr, "[VERBOSE] TLS connection done\n");
            }
            /* ask again capability request but in TLS mode */
            if (hydra_send(sock, buffer1, strlen(buffer1), 0) < 0)
              hydra_child_exit(2);
            buf = pop3_read_server_capacity(sock);
            if (buf == NULL)
              hydra_child_exit(2);
          }
	}
      }
#endif

      if ((strstr(buf, "LOGIN") == NULL) && (strstr(buf, "NTLM") != NULL)) {
        pop3_auth_mechanism = AUTH_NTLM;
      }
#ifdef LIBOPENSSLNEW
      if ((strstr(buf, "LOGIN") == NULL) && (strstr(buf, "DIGEST-MD5") != NULL)) {
        pop3_auth_mechanism = AUTH_DIGESTMD5;
      }

      if ((strstr(buf, "LOGIN") == NULL) && (strstr(buf, "CRAM-SHA256") != NULL)) {
        pop3_auth_mechanism = AUTH_CRAMSHA256;
      }

      if ((strstr(buf, "LOGIN") == NULL) && (strstr(buf, "CRAM-SHA1") != NULL)) {
        pop3_auth_mechanism = AUTH_CRAMSHA1;
      }

      if ((strstr(buf, "LOGIN") == NULL) && (strstr(buf, "CRAM-MD5") != NULL)) {
        pop3_auth_mechanism = AUTH_CRAMMD5;
      }
#endif

      if ((strstr(buf, "LOGIN") == NULL) && (strstr(buf, "PLAIN") != NULL)) {
        pop3_auth_mechanism = AUTH_PLAIN;
      }

      if (strstr(buf, "LOGIN") != NULL) {
        pop3_auth_mechanism = AUTH_LOGIN;
      }

      if (strstr(buf, "SASL") == NULL) {
#ifdef LIBOPENSSLNEW
        if (strlen(apop_challenge) == 0) {
          pop3_auth_mechanism = AUTH_CLEAR;
        } else {
          pop3_auth_mechanism = AUTH_APOP;
        }
#else
        pop3_auth_mechanism = AUTH_CLEAR;
#endif

      }
      free(buf);

      if ((miscptr != NULL) && (strlen(miscptr) > 0)) {
        int i;

        for (i = 0; i < strlen(miscptr); i++)
          miscptr[i] = (char) toupper((int) miscptr[i]);

        if (strncmp(miscptr, "CLEAR", 5) == 0)
          pop3_auth_mechanism = AUTH_CLEAR;

        if (strncmp(miscptr, "LOGIN", 5) == 0)
          pop3_auth_mechanism = AUTH_LOGIN;

        if (strncmp(miscptr, "PLAIN", 5) == 0)
          pop3_auth_mechanism = AUTH_PLAIN;

#ifdef LIBOPENSSLNEW
        if (strncmp(miscptr, "APOP", 4) == 0)
          pop3_auth_mechanism = AUTH_APOP;

        if (strncmp(miscptr, "CRAM-MD5", 8) == 0)
          pop3_auth_mechanism = AUTH_CRAMMD5;

        if (strncmp(miscptr, "CRAM-SHA1", 9) == 0)
          pop3_auth_mechanism = AUTH_CRAMSHA1;

        if (strncmp(miscptr, "CRAM-SHA256", 11) == 0)
          pop3_auth_mechanism = AUTH_CRAMSHA256;

        if (strncmp(miscptr, "DIGEST-MD5", 10) == 0)
          pop3_auth_mechanism = AUTH_DIGESTMD5;
#endif

        if (strncmp(miscptr, "NTLM", 4) == 0)
          pop3_auth_mechanism = AUTH_NTLM;

      }

      if (verbose) {
        switch (pop3_auth_mechanism) {
        case AUTH_CLEAR:
          hydra_report(stderr, "[VERBOSE] using POP3 CLEAR LOGIN mechanism\n");
          break;
        case AUTH_LOGIN:
          hydra_report(stderr, "[VERBOSE] using POP3 LOGIN AUTH mechanism\n");
          break;
        case AUTH_PLAIN:
          hydra_report(stderr, "[VERBOSE] using POP3 PLAIN AUTH mechanism\n");
          break;
        case AUTH_APOP:
#ifdef LIBOPENSSLNEW
          if (strlen(apop_challenge) == 0) {
            hydra_report(stderr, "[VERBOSE] APOP not supported by server, using clear login\n");
            pop3_auth_mechanism = AUTH_CLEAR;
          } else {
            hydra_report(stderr, "[VERBOSE] using POP3 APOP AUTH mechanism\n");
          }
#else
          pop3_auth_mechanism = AUTH_CLEAR;
#endif
          break;
#ifdef LIBOPENSSLNEW
        case AUTH_CRAMMD5:
          hydra_report(stderr, "[VERBOSE] using POP3 CRAM-MD5 AUTH mechanism\n");
          break;
        case AUTH_CRAMSHA1:
          hydra_report(stderr, "[VERBOSE] using POP3 CRAM-SHA1 AUTH mechanism\n");
          break;
        case AUTH_CRAMSHA256:
          hydra_report(stderr, "[VERBOSE] using POP3 CRAM-SHA256 AUTH mechanism\n");
          break;
        case AUTH_DIGESTMD5:
          hydra_report(stderr, "[VERBOSE] using POP3 DIGEST-MD5 AUTH mechanism\n");
          break;
#endif
        case AUTH_NTLM:
          hydra_report(stderr, "[VERBOSE] using POP3 NTLM AUTH mechanism\n");
          break;

        }
      }

      next_run = 2;
      break;
    case 2:                    /* run the cracking function */
      next_run = start_pop3(sock, ip, port, options, miscptr, fp);
      break;
    case 3:                    /* clean exit */
      if (sock >= 0)
        sock = hydra_disconnect(sock);
      hydra_child_exit(0);
      return;
    default:
      hydra_report(stderr, "[ERROR] Caught unknown return code, exiting!\n");
      hydra_child_exit(0);
    }
    run = next_run;
  }
}
