/*

Hydra Form Module
-----------------

The hydra form can be used to carry out a brute-force attack on simple 
web-based login forms that require username and password variables via 
either a GET or POST request.

The module works similarly to the HTTP basic auth module and will honour
proxy mode (with authenticaion) as well as SSL. The module can be invoked
with the service names of "http-get-form", "http-post-form",
"https-get-form" and "https-post-form".

Here's a couple of examples: -

./hydra -l "<userID>" -P pass.txt 10.221.64.12 http-post-form
"/irmlab2/testsso-auth.do:ID=^USER^&Password=^PASS^:Invalid Password"

./hydra -S -s 443 -l "<username>" -P pass.txt 10.221.64.2 https-get-form 
"/irmlab1/vulnapp.php:username=^USER^&pass=^PASS^:incorrect"

The option field (following the service field) takes three ":" separated
values and an optional fourth value, the first is the page on the server
to GET or POST to, the second is the POST/GET variables (taken from either
the browser, or a proxy such as PAROS) with the varying usernames and passwords
in the "^USER^" and "^PASS^" placeholders, the third is the string that it
checks for an *invalid* or *valid* login - any exception to this is counted
as a success.
So please:
 * invalid condition login should be preceded by "F="
 * valid condition login should be preceded by "S=".
By default, if no header is found the condition is assume to be a fail,
so checking for *invalid* login.
The fourth optional value, can be a 'C' to define a different page to GET
initial cookies from.

If you specify the verbose flag (-v) it will show you the response from the 
HTTP server which is useful for checking the result of a failed login to 
find something to pattern match against.

Module initially written by Phil Robinson, IRM Plc (releases@irmplc.com),
rewritten by David Maciejak
the strrep function was copied from bdarr(at)sse.fu.hac.com

Fix and issue with strtok use and implement 1 step location follow if HTTP
3xx code is returned (david dot maciejak at gmail dot com)

Added fail or success condition, getting cookies, and allow 5 redirections by david

*/

#include "hydra-mod.h"

extern char *HYDRA_EXIT;
char *buf;
char *cond;

int success_cond = 0;
int getcookie = 1;
int auth_flag = 0;

char redirected_url_buff[2048] = "";
int redirected_flag = 0;
#define MAX_REDIRECT 5
int redirected_cpt = MAX_REDIRECT;
char cookie[2048] = "";

extern char *webtarget;
extern char *slash;
int webport, freemischttpform = 0;
char bufferurl[1024], cookieurl[1024] = "", userheader[1024] = "", *url, *variables, *optional1;

int strpos(char *str, char *target) {
  char *res = strstr(str, target);

  if (res == NULL)
    return -1;
  else
    return res - str;
}

char *strrep(char *string, char *oldpiece, char *newpiece) {
  int str_index, newstr_index, oldpiece_index, end, new_len, old_len, cpy_len;
  char *c, oldstring[1024];
  static char newstring[1024];

  if (string == NULL || oldpiece == NULL || newpiece == NULL || strlen(string) >= sizeof(oldstring) || (strlen(string) + strlen(newpiece) - strlen(oldpiece) >= sizeof(newstring) && strlen(string) > strlen(oldpiece) ))
    return NULL;

  strcpy(newstring, string);
  strcpy(oldstring, string);

  while ((c = (char *) strstr(oldstring, oldpiece)) != NULL) {
    c = (char *) strstr(oldstring, oldpiece);
    new_len = strlen(newpiece);
    old_len = strlen(oldpiece);
    end = strlen(oldstring) - old_len;
    oldpiece_index = c - oldstring;
    newstr_index = 0;
    str_index = 0;
    while (str_index <= end && c != NULL) {
      /* Copy characters from the left of matched pattern occurence */
      cpy_len = oldpiece_index - str_index;
      strncpy(newstring + newstr_index, oldstring + str_index, cpy_len);
      newstr_index += cpy_len;
      str_index += cpy_len;

      /* Copy replacement characters instead of matched pattern */
      strcpy(newstring + newstr_index, newpiece);
      newstr_index += new_len;
      str_index += old_len;
      /* Check for another pattern match */
      if ((c = (char *) strstr(oldstring + str_index, oldpiece)) != NULL)
        oldpiece_index = c - oldstring;
    }
    /* Copy remaining characters from the right of last matched pattern */
    strcpy(newstring + newstr_index, oldstring + str_index);
    strcpy(oldstring, newstring);
  }
  return newstring;
}

/*
int analyze_server_response(int socket)
return 0 or 1 when the cond regex is matched
*/
int analyze_server_response(int s) {
  int runs = 0;

  while ((buf = hydra_receive_line(s)) != NULL) {
    runs++;
    //check for http redirection
    if (strstr(buf, "HTTP/1.1 3") != NULL || strstr(buf, "Status: 3") != NULL) {
      redirected_flag = 1;
    } else if (strstr(buf, "HTTP/1.1 401") != NULL) {
      auth_flag = 1;
    } else if ((strstr(buf, "HTTP/1.1 403") != NULL) || (strstr(buf, "HTTP/1.1 404") != NULL)) {
      return !success_cond;
    }

    if (hydra_strcasestr(buf, "Location: ") != NULL) {
      char *startloc, *endloc;
      char str[2048];

      startloc = hydra_strcasestr(buf, "Location: ") + strlen("Location: ");
      strncpy(str, startloc, sizeof(str) - 1);
      str[sizeof(str) - 1] = 0;
      endloc = strchr(str, '\n');
      if (endloc != NULL)
        *endloc = 0;
      endloc = strchr(str, '\r');
      if (endloc != NULL)
        *endloc = 0;
      strcpy(redirected_url_buff, str);
    }
    //there can be multiple cookies
    if (hydra_strcasestr(buf, "Set-Cookie: ") != NULL) {
      char *cookiebuf = buf;

      do {
        char *startcookie, *endcookie1, *endcookie2;
        char str[2048], tmpcookie[2048] = "", tmpname[128] = "", *ptr, *ptr2;

        memset(str, 0, sizeof(str));
        startcookie = hydra_strcasestr(cookiebuf, "Set-Cookie: ") + strlen("Set-Cookie: ");
        strncpy(str, startcookie, sizeof(str) - 1);
        str[sizeof(str) - 1] = 0;
        endcookie1 = strchr(str, '\n');
        endcookie2 = strchr(str, ';');
        //terminate string after cookie data
        if (endcookie1 != NULL && endcookie1 < endcookie2)
          *endcookie1 = 0;
        else
          *endcookie2 = 0;
        // is the cookie already there? if yes, remove it!
        if (index(startcookie, '=') != NULL && (ptr = index(startcookie, '=')) - startcookie + 1 <= sizeof(tmpname)) {
          strncpy(tmpname, startcookie, sizeof(tmpname) - 2);
          tmpname[sizeof(tmpname) - 2] = 0;
          ptr = index(tmpname, '=');
          *(++ptr) = 0;
          // is the cookie already in the cookiejar? (so, does it have to be replaced?)
          if ((ptr = hydra_strcasestr(cookie, tmpname)) != NULL) {
            // yes it is.
            // if the cookie is not in the beginning of the cookiejar, copy the ones before
            if (ptr != cookie && *(ptr - 1) == ' ') {
              strncpy(tmpcookie, cookie, ptr - cookie - 2);
              tmpcookie[ptr - cookie - 2] = 0;
            }
            ptr += strlen(tmpname);
            // if there are any cookies after this one in the cookiejar, copy them over
            if ((ptr2 = strstr(ptr, "; ")) != NULL) {
              ptr2 += 2;
              strncat(tmpcookie, ptr2, sizeof(tmpcookie) - strlen(tmpcookie) - 1);
            }
            if (debug)
              printf("[DEBUG] removing cookie %s in jar\n before: %s\n after:  %s\n", tmpname, cookie, tmpcookie);
            strcpy(cookie, tmpcookie);
          }
        }
        ptr = index(str, '=');
        // only copy the cookie if it has a value (otherwise the server wants to delete the cookie
        if (ptr != NULL && *(ptr + 1) != ';' && *(ptr + 1) != 0 && *(ptr + 1) != '\n' && *(ptr + 1) != '\r') {
          if (strlen(cookie) > 0)
            strncat(cookie, "; ", sizeof(cookie) - strlen(cookie) - 1);
          strncat(cookie, str, sizeof(cookie) - strlen(cookie) - 1);
        }
        cookiebuf = startcookie;
      }
      while (hydra_strcasestr(cookiebuf, "Set-Cookie: ") != NULL);
    }
#ifdef HAVE_PCRE
    if (hydra_string_match(buf, cond)) {
#else
    if (strstr(buf, cond) != NULL) {
#endif
      free(buf);
      return !success_cond;
    }
    free(buf);
  }
  if (runs == 0 && success_cond == 0)
    return !success_cond;
  else 
    return success_cond;
}

void hydra_reconnect(int s, char *ip, int port, unsigned char options) {
  if (s >= 0)
    s = hydra_disconnect(s);
  if ((options & OPTION_SSL) == 0) {
    s = hydra_connect_tcp(ip, port);
  } else {
    s = hydra_connect_ssl(ip, port);
  }
}

int start_http_form(int s, char *ip, int port, unsigned char options, char *miscptr, FILE * fp, char *type) {
  char *empty = "";
  char *login, *pass, buffer[4096];
  char header[2048], *upd3variables;
  int found = 0, i, j;

  memset(header, 0, sizeof(header));
  cookie[0] = 0;                // reset cookies from potential previous attempt

  if (strlen(login = hydra_get_next_login()) == 0)
    login = empty;
  if (strlen(pass = hydra_get_next_password()) == 0)
    pass = empty;
  upd3variables = strrep(variables, "^PASS^", pass);
  upd3variables = strrep(upd3variables, "^USER^", login);

  /* again: no snprintf to be portable. dont worry, buffer cant overflow */
  if (use_proxy == 1 && proxy_authentication != NULL) {
    // proxy with authentication
    if (getcookie) {
      //doing a GET to save cookies
      sprintf(buffer, "GET http://%s:%d%.600s HTTP/1.0\r\nHost: %s\r\nProxy-Authorization: Basic %s\r\nUser-Agent: Mozilla 5.0 (Hydra Proxy Auth)\r\n%s%s\r\n",
              webtarget, webport, cookieurl, webtarget, proxy_authentication, header, userheader);
      if (hydra_send(s, buffer, strlen(buffer), 0) < 0) {
        return 1;
      }
      analyze_server_response(s);
      if (strlen(cookie) > 0) {
        sprintf(header, "Cookie: %s\r\n", cookie);
      }
      hydra_reconnect(s, ip, port, options);
    }

    if (strcmp(type, "POST") == 0) {
      sprintf(buffer,
              "POST http://%s:%d%.600s HTTP/1.0\r\nHost: %s\r\nProxy-Authorization: Basic %s\r\nUser-Agent: Mozilla/5.0 (Hydra Proxy Auth)\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: %d\r\n%s%s\r\n%s",
              webtarget, webport, url, webtarget, proxy_authentication, (int) strlen(upd3variables), header, userheader, upd3variables);
      if (hydra_send(s, buffer, strlen(buffer), 0) < 0) {
        return 1;
      }
    } else {
      sprintf(buffer,
              "GET http://%s:%d%.600s?%s HTTP/1.0\r\nHost: %s\r\nProxy-Authorization: Basic %s\r\nUser-Agent: Mozilla/5.0 (Hydra Proxy Auth)\r\n%s%s\r\n",
              webtarget, webport, url, upd3variables, webtarget, proxy_authentication, header, userheader);
      if (hydra_send(s, buffer, strlen(buffer), 0) < 0) {
        return 1;
      }
    }
  } else {
    if (use_proxy == 1) {
      // proxy without authentication
      if (getcookie) {
        //doing a GET to get cookies
        sprintf(buffer, "GET http://%s:%d%.600s HTTP/1.0\r\nHost: %s\r\nUser-Agent: Mozilla/5.0 (Hydra Proxy)\r\n%s%s\r\n", webtarget, webport, cookieurl, webtarget, header, userheader);
        if (hydra_send(s, buffer, strlen(buffer), 0) < 0) {
          return 1;
        }
        analyze_server_response(s);
        if (strlen(cookie) > 0) {
          sprintf(header, "Cookie: %s\r\n", cookie);
        }
        hydra_reconnect(s, ip, port, options);
      }

      if (strcmp(type, "POST") == 0) {
        sprintf(buffer,
                "POST http://%s:%d%.600s HTTP/1.0\r\nHost: %s\r\nUser-Agent: Mozilla/5.0 (Hydra)\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: %d\r\n%s%s\r\n%s",
                webtarget, webport, url, webtarget, (int) strlen(upd3variables), header, userheader, upd3variables);
        if (hydra_send(s, buffer, strlen(buffer), 0) < 0) {
          return 1;
        }
      } else {
        sprintf(buffer, "GET http://%s:%d%.600s?%s HTTP/1.0\r\nHost: %s\r\nUser-Agent: Mozilla/5.0 (Hydra)\r\n%s%s\r\n", webtarget, webport, url, upd3variables, webtarget, header, userheader);
        if (hydra_send(s, buffer, strlen(buffer), 0) < 0) {
          return 1;
        }
      }
    } else {
      // direct web server, no proxy
      if (getcookie) {
        //doing a GET to save cookies
        sprintf(buffer, "GET %.600s HTTP/1.0\r\nHost: %s\r\nUser-Agent: Mozilla/5.0 (Hydra)\r\n%s\r\n", cookieurl, webtarget, userheader);
        if (hydra_send(s, buffer, strlen(buffer), 0) < 0) {
          return 1;
        }
        analyze_server_response(s);
        if (strlen(cookie) > 0) {
          sprintf(header, "Cookie: %s\r\n", cookie);
        }
        hydra_reconnect(s, ip, port, options);
      }

      if (strcmp(type, "POST") == 0) {
        sprintf(buffer,
                "POST %.600s HTTP/1.0\r\nHost: %s\r\nUser-Agent: Mozilla/5.0 (Hydra)\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: %d\r\n%s%s\r\n%s",
                url, webtarget, (int) strlen(upd3variables), header, userheader, upd3variables);
        if (hydra_send(s, buffer, strlen(buffer), 0) < 0) {
          return 1;
        }
      } else {
        sprintf(buffer, "GET %.600s?%s HTTP/1.0\r\nHost: %s\r\nUser-Agent: Mozilla/5.0 (Hydra)\r\n%s%s\r\n", url, upd3variables, webtarget, header, userheader);
        if (hydra_send(s, buffer, strlen(buffer), 0) < 0) {
          return 1;
        }
      }
    }
  }

  found = analyze_server_response(s);
  if (auth_flag) {              // we received a 401 error - user using wrong module
    hydra_report(stderr, "Error: the target is using HTTP auth, not a web form, received HTTP error code 401. Use module \"http%s-get\" instead.\n",
                 (options & OPTION_SSL) > 0 ? "s" : "");
    return 4;
  }
  if (strlen(cookie) > 0) {
    sprintf(header, "Cookie: %s\r\n", cookie);
  }
  //if page was redirected, follow the location header
  redirected_cpt = MAX_REDIRECT;
  while (!found && redirected_flag && (redirected_url_buff[0] != 0) && (redirected_cpt > 0)) {
    //we have to split the location
    char *startloc, *endloc;
    char str[2048];
    char str2[2048];
    char str3[2048];

    redirected_cpt--;
    redirected_flag = 0;
    //check if the redirect page contains the fail/success condition
#ifdef HAVE_PCRE
    if (hydra_string_match(redirected_url_buff, cond)) {
#else
    if (strstr(redirected_url_buff, cond) != NULL) {
#endif
      found = !success_cond;
    } else {
      //location could be either absolute http(s):// or / something
      //or relative
      startloc = strstr(redirected_url_buff, "://");
      if (startloc != NULL) {
        startloc += strlen("://");

        if ((endloc=strchr(startloc, '\r')) != NULL) {
          startloc[endloc - startloc] = 0;
        }
        if ((endloc=strchr(startloc, '\n')) != NULL) {
          startloc[endloc - startloc] = 0;
        }
        strcpy(str, startloc);

        endloc = strchr(str, '/');
        if (endloc != NULL) {
          strncpy(str2, str, endloc - str);
          str2[endloc - str] = 0;
        }
        else
            strncpy(str2, str, sizeof(str));

        if (strlen(str) - strlen(str2) == 0) {
          strcpy(str3, "/");
        } else {
          strncpy(str3, str + strlen(str2), strlen(str) - strlen(str2) - 1);
          str3[strlen(str) - strlen(str2) - 1] = 0;
        }
      } else {
        strncpy(str2, webtarget, sizeof(str2));
        if (redirected_url_buff[0] != '/') {
          //it's a relative path, so we have to concatenate it
          //with the path from the first url given
          char *urlpath;
          char urlpath_extracted[2048];
          memset(urlpath_extracted, 0, sizeof(urlpath_extracted));

          urlpath=strrchr(url, '/');
          if (urlpath != NULL) {
            strncpy(urlpath_extracted, url, urlpath-url);
            sprintf(str3, "%.1000s/%.1000s", urlpath_extracted, redirected_url_buff);
          } else {
            sprintf(str3, "%.1000s/%.1000s", url, redirected_url_buff);
          }
        } else
          strncpy(str3, redirected_url_buff, sizeof(str3));
       if (debug)
         hydra_report(stderr, "[DEBUG] host=%s redirect=%s origin=%s\n", str2, str3,url);
      }
      if (str3[0] != '/') {
        j = strlen(str3);
        str3[j + 1] = 0;
        for (i = j; i > 0; i--)
          str3[i] = str3[i - 1];
        str3[0] = '/';
      }

      if (verbose)
        hydra_report(stderr, "[VERBOSE] Page redirected to http://%s%s\n", str2, str3);

      //re-use the code above to check for proxy use
      if (use_proxy == 1 && proxy_authentication != NULL) {
        // proxy with authentication
        sprintf(buffer, "GET http://%s:%d%.600s HTTP/1.0\r\nHost: %s\r\nProxy-Authorization: Basic %s\r\nUser-Agent: Mozilla/4.0 (Hydra)\r\n%s\r\n",
                webtarget, webport, str3, str2, proxy_authentication, header);
      } else {
        if (use_proxy == 1) {
          // proxy without authentication
          sprintf(buffer, "GET http://%s:%d%.600s HTTP/1.0\r\nHost: %s\r\nUser-Agent: Mozilla/4.0 (Hydra)\r\n%s\r\n", webtarget, webport, str3, str2, header);
        } else {
          //direct web server, no proxy
          sprintf(buffer, "GET %.600s HTTP/1.0\r\nHost: %s\r\nUser-Agent: Mozilla/4.0 (Hydra)\r\n%s\r\n", str3, str2, header);
        }
      }

      hydra_reconnect(s, ip, port, options);

      if (hydra_send(s, buffer, strlen(buffer), 0) < 0) {
        return 1;
      }
      found = analyze_server_response(s);
      if (strlen(cookie) > 0) {
        sprintf(header, "Cookie: %s\r\n", cookie);
      }
    }
  }

  //if the last status is still 3xx, set it as a false
  if (found != 1 && redirected_flag == 0 && redirected_cpt >= 0) {
    hydra_report_found_host(port, ip, "www-form", fp);
    hydra_completed_pair_found();
  } else {
    hydra_completed_pair();
  }
  return 1;
}

void service_http_form(char *ip, int sp, unsigned char options, char *miscptr, FILE * fp, int port, char *type) {
  int run = 1, next_run = 1, sock = -1;
  int myport = PORT_HTTP, mysslport = PORT_HTTP_SSL;
  char *ptr, *ptr2;

  hydra_register_socket(sp);

  if (webtarget != NULL && (webtarget = strstr(miscptr, "://")) != NULL) {
    webtarget += strlen("://");
    if ((ptr2 = index(webtarget, ':')) != NULL) {       /* step over port if present */
      *ptr2 = 0;
      ptr2++;
      ptr = ptr2;
      if (*ptr == '/' || (ptr = index(ptr2, '/')) != NULL)
        miscptr = ptr;
      else
        miscptr = slash;        /* to make things easier to user */
    } else if ((ptr2 = index(webtarget, '/')) != NULL) {
      if (freemischttpform == 0) {
        freemischttpform = 1;
        miscptr = malloc(strlen(ptr2) + 1);
        strcpy(miscptr, ptr2);
        *ptr2 = 0;
      }
    } else
      webtarget = NULL;
  }
  if (cmdlinetarget != NULL && webtarget == NULL)
    webtarget = cmdlinetarget;
  else if (webtarget == NULL && cmdlinetarget == NULL)
    webtarget = hydra_address2string(ip);
  if (port != 0)
    webport = port;
  else if ((options & OPTION_SSL) == 0)
    webport = myport;
  else
    webport = mysslport;

  sprintf(bufferurl, "%.1000s", miscptr);
  url = strtok(bufferurl, ":");
  variables = strtok(NULL, ":");
  cond = strtok(NULL, ":");
  sprintf(cookieurl, "%.1000s", url);

  //condition now have to contain F or S to set the fail or success condition
  if (cond && (strpos(cond, "F=") == 0)) {
    success_cond = 0;
    cond += 2;
  } else if (cond && (strpos(cond, "S=") == 0)) {
    success_cond = 1;
    cond += 2;
  } else {
    //by default condition is a fail
    success_cond = 0;
  }
  
  while ((optional1 = strtok(NULL, ":")) != NULL) {
    switch(optional1[0]) {
      case 'c': // fall through
      case 'C':
          sprintf(cookieurl, "%.1000s", optional1 + 2);
        break;
      case 'h': // fall through
      case 'H':
          if (sizeof(userheader) - strlen(userheader) > 4) {
            strncat(userheader, optional1 + 2, sizeof(userheader) - strlen(userheader) - 4);
            strcat(userheader, ":");
            optional1 = strtok(NULL, ":");
            strncat(userheader, optional1, sizeof(userheader) - strlen(userheader) - 3);
            strcat(userheader, "\r\n");
          }
        break;
      // no default
    }
  }

  while (1) {
    if (run == 2) {
      if (memcmp(hydra_get_next_pair(), &HYDRA_EXIT, sizeof(HYDRA_EXIT)) == 0) {
        if (freemischttpform)
          free(miscptr);
        freemischttpform = 0;
        hydra_child_exit(1);
      }
    }
    switch (run) {
    case 1:                    /* connect and service init function */
      {
        if (sock >= 0)
          sock = hydra_disconnect(sock);
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
          if (freemischttpform)
            free(miscptr);
          freemischttpform = 0;
          hydra_child_exit(1);
        }
        next_run = 2;
        break;
      }
    case 2:                    /* run the cracking function */
      next_run = start_http_form(sock, ip, port, options, miscptr, fp, type);
      break;
    case 3:                    /* clean exit */
      if (sock >= 0)
        sock = hydra_disconnect(sock);
      if (freemischttpform)
        free(miscptr);
      freemischttpform = 0;
      hydra_child_exit(0);
      break;
    case 4:                    /* silent error exit */
      if (sock >= 0)
        sock = hydra_disconnect(sock);
      if (freemischttpform)
        free(miscptr);
      freemischttpform = 0;
      hydra_child_exit(1);
      break;
    default:
      if (freemischttpform)
        free(miscptr);
      freemischttpform = 0;
      hydra_report(stderr, "Caught unknown return code, exiting!\n");
      hydra_child_exit(0);
    }
    run = next_run;
  }
  if (freemischttpform)
    free(miscptr);
}

void service_http_get_form(char *ip, int sp, unsigned char options, char *miscptr, FILE * fp, int port) {
  service_http_form(ip, sp, options, miscptr, fp, port, "GET");
}

void service_http_post_form(char *ip, int sp, unsigned char options, char *miscptr, FILE * fp, int port) {
  service_http_form(ip, sp, options, miscptr, fp, port, "POST");
}
