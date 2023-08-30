/*
 * *** Le Fuzzer Con ***
 * Claire Lex, 2022 - https://github.com/claire-lex/le-fuzzer-con
 *
 * Le Fuzzer Con* (LFC) creates network packets as random byte arrays that are
 * sent to a server to fuzz it. The thing with LFC is that we can lock bytes that
 * should not be random (e.g. a valid header). The aim is to create packets that
 * are not directly dropped by servers, so that our fuzzed frames reach the
 * parsing and processing implementations and cover more code. LFC keeps no track
 * of previous packets (it's just random) and gives no feedback about what
 * happens server-side, you have to monitor it yourself.
 *
 * * "Le fuzzer con" means "The dumb fuzzer" in French, because it is meant to be
 * dumb (i.e. stateless and protocol-independent). f you want a fine-tuned
 * fuzzing process, I recommend you use a real fuzzer instead.
 *
 * Licensed under GPLv3.
*/

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdbool.h>
#include <getopt.h>
#include <ctype.h>
#include <limits.h>
#include <regex.h>
#include <signal.h>
#include <time.h>
/* Network */
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

/*****************************************************************************/
/* Constants                                                                 */
/*****************************************************************************/

#define USAGE ""							\
  "./le-fuzzer-con [-h] [-v] [-m min_size] [-n max_size] [-l locked_bytes]\n" \
  "                host (--help)" \
  "\n"
#define HELP "" \
  "Another dumb network fuzzer, but not the worst one.\n" \
  "Generates network packets for fuzzing with random content except for bytes\n" \
  "that should not be random to be accepted by the remote server (e.g. headers)." \
  "\n\n" \
  "  host            Target information with format proto://ip:port.\n" \
  "                  Ex: udp://192.168.1.100:4444" \
  "\n\n" \
  "Arguments:\n" \
  "  -l    --lock    List of fixed bytes (same for all packets) Format is:\n" \
  "                  location1:content1;loc2:con2;... Content can also be a keyword.\n" \
  "                  (eg: 0:\\x06\\x10\\xLL\\xLL;-1:\\x01 -> Header on 4B ending with\n" \
  "                  total packet length on 2B, last byte is always \\x01)\n" \
  "  -m    --min     Minimum size for packets (default: 1).\n" \
  "  -n    --max     Maximum size for packets (default: 20 (arbitrary)).\n" \
  "  -d    --delay   Delay in ms before sending the next packet (default: 0).\n" \
  "  -s    --step    Step by step mode, wait for user input to send the next frame.\n" \
  "  -v    --verbose Verbose mode.\n" \
  "\n"

#define MIN_SIZE 1
#define MAX_SIZE 20 /* Arbitrary */
#define DELIM ";"

#define LOCK_REGEX "^([-0-9]+):([[0-9a-fA-F\\xL]+)$"
#define MAX_LOCKS 128 /* Arbitrary */

#define TARGET_REGEX "^(tcp|udp)://([0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+):([0-9]+)$"

/* Global */
bool VERBOSE = false;
bool STEP = false;
bool LOOP = false;

/*****************************************************************************/
/* Structure definition for settings                                         */
/*****************************************************************************/

typedef struct target {
  char proto[4];
  struct in_addr ip;
  unsigned int port;
} target_t;
typedef struct lock {
  int position; /* Position can be < 0 */
  size_t length;
  char *bytes;
} lock_t;
typedef struct len {
  bool set;
  int position;
  size_t length;
} len_t;

typedef struct args {
  target_t target;
  unsigned int min_size;
  unsigned int max_size;
  unsigned int delay;
  unsigned int total;
  lock_t *locks[MAX_LOCKS];
  unsigned int locks_nb;
  len_t length;
} args_t;

/*****************************************************************************/
/* Print macros and functions                                                */
/*****************************************************************************/

#pragma GCC diagnostic ignored "-Wunused-value"
#define ERROR(x) { fprintf(stderr, "[ERROR] %s\n", x); -1; }

#define PRINT(x) printf("[LFC] %s\n", x)
#define PRINTC(x) printf("[LFC] %c\n", x)
#define VPRINT(x) if (VERBOSE) printf("[INFO] %s\n", x)
#define VPRINTA(x, y) if (VERBOSE) printf("[INFO] %s: %u\n", x, y)

void print_bytes(char *bytes, unsigned int size) {
  for (unsigned int i = 0; i < size; i++)
    printf("\\x%02x", bytes[i]);
  printf("\n");
}

/*****************************************************************************/
/* Conversion stuff                                                          */
/*****************************************************************************/

int isnum(char *str) {
  for (unsigned int i = 0; i < strlen(str); i++)
    if (!isdigit(str[i]))
      return (-1);
  return (0);
}

int str_to_bytes(char *str, char *bytes) {
  unsigned int ct;
  
  ct = 0;
  for (unsigned int i = 0; i <= strlen(str); i += 2) {
    char buf[3] = { str[i], str[i+1], 0 };
    bytes[ct] = strtol(buf, NULL, 16);
    ct++;
  }
  return (ct - 1);
}

/*****************************************************************************/
/* Network                                                                      */
/*****************************************************************************/

int create_socket(args_t *settings) {
  int sock;

  sock = -1;
  if (!strcmp(settings->target.proto, "udp"))
    sock = socket(AF_INET, SOCK_DGRAM, 0);
  else if (!strcmp(settings->target.proto, "tcp"))
    sock = socket(AF_INET, SOCK_STREAM, 0);
  if (sock < 0)
    return(ERROR("Failed to create socket."));
  return (sock);
}

/*****************************************************************************/
/* Signals handling                                                          */
/*****************************************************************************/

void sigint_handler(int sig_num)
{
  /* We use a global variable that will properly exit the fuzzing loop. */
  (void) sig_num;
  LOOP = false;
  printf("\nExiting.\n");
}

/*****************************************************************************/
/* Settings initialization                                                   */
/*****************************************************************************/

/* Store target information into a target_t structure (in settings_t).
 * Target argument format is "proto://ip:port" where :
 * - proto: either "tcp" or "udp"
 * - ip; IPv4 address ("A.B.C.D")
 * - port: Port number (1-65535)
*/

int set_target(args_t *settings, char *arg) {
  regex_t regex;
  regmatch_t pmatch[4];
  char *tmp_ip;

  memset(pmatch, 0, sizeof(regmatch_t) * 4);
  if (regcomp(&regex, TARGET_REGEX, REG_EXTENDED))
    return (ERROR("Error while compiling regex for target arg."));  
  if (regexec(&regex, arg, 4, pmatch, 0) == REG_NOMATCH) {
    regfree(&regex);
    return (ERROR("Invalid syntax for target."));
  }
  memset(settings->target.proto, 0, 4);
  /* Proto */
  strncpy(settings->target.proto, &arg[pmatch[1].rm_so], 3);
  /* IP */
  if ((tmp_ip = malloc(pmatch[2].rm_eo - pmatch[2].rm_so + 1)) == NULL) {
    regfree(&regex);
    return (ERROR("Could not allocate memory for lock."));
  }
  memset(tmp_ip, 0, pmatch[2].rm_eo - pmatch[2].rm_so + 1);
  strncpy(tmp_ip, &arg[pmatch[2].rm_so], pmatch[2].rm_eo - pmatch[2].rm_so);
  inet_aton(tmp_ip, &(settings->target.ip));
  free(tmp_ip);
  /* Port */
  settings->target.port = atoi(&arg[pmatch[3].rm_so]);
  if (settings->target.port <= 0 || settings->target.port >= 65535) {
    regfree(&regex);
    return (ERROR("Port has invalid range."));
  }
  regfree(&regex);  
  return (0);
}

int set_content(args_t *settings, char *arg, size_t length, char *bytes) {
  unsigned int i, ct, ret;
  char *str;

  if ((str = malloc(length + 1)) == NULL)
    return (ERROR("Could not allocate memory for lock."));
  memset(str, 0, length + 1);
  /* Removing delimiter because it's an easier solution... */
  ct = 0;
  for (i = 0; i < length; i++) {
    if (arg[i] != '\\' && arg[i] != 'x') {
      str[ct] = arg[i];
      ct++;
    }
  }
  str[ct] = 0;
  /* Replacing length modifiers. */
  ct = 0;
  for (i = 0; i <= strlen(str); i += 2) {
    if (str[i] == 'L') {
      if (!settings->length.set) {
	settings->length.position = settings->locks[settings->locks_nb]->position + i / 2;
	settings->length.set = true;
      }
      str[i] = '0';
      str[i + 1] = '0';
      ct++;
    }
  }
  if (ct > 0)
    settings->length.length = ct;
  /* Convert it to byte array */
  ret = str_to_bytes(str, bytes);
  free(str);
  return (ret);
}

/* Store one lock information into a lock_t structure (in settings_t).
 * Isolated lock argument format is "position:content" where :
 * - position: position in the final packet where content should be placed
 * - content: byte array with format \x00\x00\x00..."
*/

int create_lock(args_t *settings, char *arg, regmatch_t pos, regmatch_t content) {
  char *tmp_position; /* Will be converted to uint for storage */
  char *bytes;
  unsigned int length;
  
  if ((settings->locks[settings->locks_nb] = malloc(sizeof(lock_t))) == NULL)
    return (ERROR("Could not allocate memory for lock."));
  /* Storing position from matching string to lock struct */
  if ((tmp_position = malloc(pos.rm_eo - pos.rm_so + 1)) == NULL)
    return (ERROR("Could not allocate memory for lock."));
  memset(tmp_position, 0, pos.rm_eo - pos.rm_so + 1);
  strncpy(tmp_position, &arg[pos.rm_so], pos.rm_eo);
  settings->locks[settings->locks_nb]->position = atoi(tmp_position);
  free(tmp_position);
  /* Storing bytes info from matching string to lock struct */
  if ((bytes = malloc(content.rm_eo - content.rm_so + 1)) == NULL)
    return (ERROR("Could not allocate memory for lock."));
  memset(bytes, 0, content.rm_eo - content.rm_so + 1);
  length = set_content(settings, &arg[content.rm_so], content.rm_eo - content.rm_so, bytes);
  settings->locks[settings->locks_nb]->bytes = bytes;
  settings->locks[settings->locks_nb]->length = length;
  settings->locks_nb++;
  if (settings->locks_nb >= MAX_LOCKS)
    return (ERROR("Maximum number of locks exceeded."));
  return (0);
}

/* Parse the lock argument to extract information about locks.
 * Lock argument format is "lock1;lock2;..." where each lock contains the
 * location and content that will be fixed in a packet with format
 * "position:content"
*/
int set_lock(args_t *settings, char *optarg) {
  char *ptr;
  regex_t regex;
  regmatch_t pmatch[3];

  if (regcomp(&regex, LOCK_REGEX, REG_EXTENDED))
    return (ERROR("Error while compiling regex for lock arg."));  
  /* Split optarg to get list of positions to lock 1 by 1 */
  /* Optarg format should be: "pos1:bytes1;pos2:bytes2;..." */
  ptr = strtok(optarg, DELIM);
  while (ptr != NULL) {
    memset(pmatch, 0, sizeof(regmatch_t) * 3);
    /* ptr format should be: "pos1:bytes1", let's parse it */
    if (regexec(&regex, ptr, 3, pmatch, 0) == REG_NOMATCH) {
      regfree(&regex);
      return (ERROR("Invalid syntax for locks."));
    }
    /* Now we create a new lock structure */
    if (create_lock(settings, ptr, pmatch[1], pmatch[2]) < 0) {
      regfree(&regex);
      return (-1);
    }
    ptr = strtok(NULL, DELIM);
  }
  regfree(&regex);
  return (0);
}

int set_args(args_t *settings, int ac, char **av) {
  struct option longopts[] = {
    { "help", no_argument, NULL, 'h' },
    { "verbose", no_argument, NULL, 'v' },
    { "step", no_argument, NULL, 's' },
    { "total", required_argument, NULL, 't' },
    { "min", required_argument, NULL, 'm' },
    { "max", required_argument, NULL, 'n' },
    { "delay", required_argument, NULL, 'd'},
    { "lock", required_argument, NULL, 'l' },
    { "bitlock", required_argument, NULL, 'b' },
    { 0 }
  };
  char arg;

  /* Init */
  settings->target = (target_t){ 0 };
  settings->min_size = MIN_SIZE;
  settings->max_size = MAX_SIZE;
  settings->delay = 0;
  settings->total = 0;
  memset(settings->locks, 0, sizeof(void*) * MAX_LOCKS);
  settings->locks_nb = 0;
  settings->length.set = false;
  settings->length.position = 0;
  settings->length.length = 0;
  /* Parsing */
  while ((arg = getopt_long(ac, av, "hvst:m:n:d:l:b:", longopts, 0)) > -1
	 && arg < SCHAR_MAX) {
    if (arg == 'h') { /* Print help and exit */
      printf(HELP);
      break ;
    }
    else if (arg == 'v') { /* Enable verbose mode */
      VERBOSE = true; /* Global */
      VPRINT("Verbose mode enabled.");
    }
    else if (arg == 's') { /* Enable step by step mode */
      STEP = true; /* Global */
      VPRINT("Step-by-step mode enabled.");
    }
    else if (arg == 't') { /* Only send a defined number of requests */
      settings->total = atoi(optarg);
      VPRINT("Only the specified amount of requests will be sent.");
    }
    else if (arg == 'm') { /* Minimum size, takes unsigned int */
      if (isnum(optarg) < 0)
	return (ERROR("Minimum size should be an unsigned integer."));
      settings->min_size = atoi(optarg);
    }
    else if (arg == 'n') { /* Maximum size, takes unsigned int */
      if (isnum(optarg) < 0)
	return (ERROR("Maximum size should be an unsigned integer."));
      settings->max_size = atoi(optarg);
    }
    else if (arg == 'd') { /* Delay between packets, takes unsigned int */
      if (isnum(optarg) < 0)
	return (ERROR("Delay should be an unsigned integer."));
      settings->delay = atoi(optarg);
    }
    else if (arg == 'l') { /* Locked bytes, takes weird regex */
      if (set_lock(settings, optarg) < 0)
	return (-1);
    }
    else if (arg == 'b') { /* Locked bits, takes weirder regex */
      VPRINT("List of bits to lock:");
      VPRINT(optarg);
      PRINT("Locked bits not implemented yet.");
    }
  }
  /* There should be one remaining argument: target host (proto://ip:port) */
  while (optind < ac) {
    if (set_target(settings, av[optind]) > 0)
      return (0);
    optind++;
  }
  /* Final checks */
  if (settings->target.port == 0)
    return (ERROR("Missing target information."));
  if (settings->min_size > settings->max_size)
    return (ERROR("Minimum size must not be greater than maximum size..."));
  return (0);
}

void settings_verbose(args_t *settings) {
  if (VERBOSE) {
    printf("[INFO] Target is %s on port %d (%s)\n", inet_ntoa(settings->target.ip),
	   settings->target.port, settings->target.proto);
    printf("[INFO] Size boundaries: %u -> %u\n", settings->min_size, settings->max_size);
    VPRINT("List of bytes to lock:");
    for (unsigned int i = 0; i < settings->locks_nb; i++) {
      printf("[INFO] At position %d: ", settings->locks[i]->position);
      print_bytes(settings->locks[i]->bytes, settings->locks[i]->length);
    }
  }
}

/*****************************************************************************/
/* Fuzzing                                                                   */
/*****************************************************************************/

void random_bytes(char *packet, unsigned int size) {
  for (unsigned int i = 0; i < size; i++)
    packet[i] = rand();
}

void insert_locks(char *packet, unsigned int size, args_t *settings) {
  unsigned int j, pos;
  
  for (unsigned int i = 0; i < settings->locks_nb; i++) {
    /* Handling negative location: set bytes from end */
    if (settings->locks[i]->position < 0) {
      pos = size + settings->locks[i]->position; /* neg: size + -1 */
      for (j = 0; j + pos < size; j++)
	packet[pos++] = settings->locks[i]->bytes[j];
    }
    else if (settings->locks[i]->position + settings->locks[i]->length <= size) {
      pos = settings->locks[i]->position;
      for (j = 0; j < settings->locks[i]->length; j++)
	packet[pos++] = settings->locks[i]->bytes[j];
    }
  }
}

void insert_length(char *packet, unsigned int size, args_t *settings) {
  char len[settings->length.length];
  unsigned int i, pos;

  if (!settings->length.set)
    return ;
  pos = settings->length.length - 1;
  for (i = 0; i < settings->length.length; i++) {
    len[pos] = (size >> i*8) & 0xff;
    pos--;
  }
  /* Handling negative location: set bytes from end */
  if (settings->length.position < 0) {
    pos = size + settings->length.position;
    for (i = 0; i < settings->length.length && pos < size; i++)
      packet[pos++] = len[i];
  }
  else if (settings->length.position + settings->length.length <= size) {
    pos = settings->length.position;
    for (i = 0; i < settings->length.length; i++)
      packet[pos++] = len[i];
  }
}

int fuzz(args_t *settings) {
  struct sockaddr_in addr;
  unsigned int size;
  unsigned int ct;
  char *packet;
  int sock;
  int ret;

  ret = 0;
  LOOP = true;
  if ((sock = create_socket(settings)) < 0)
    return (-1);
  memset(&addr, 0, sizeof(struct sockaddr_in));
  addr.sin_family = AF_INET;
  addr.sin_addr = settings->target.ip;
  addr.sin_port = htons(settings->target.port);
  if (!strcmp(settings->target.proto, "tcp")) 
    if (connect(sock, (struct sockaddr*)&addr,
		(socklen_t)sizeof(struct sockaddr_in)) < 0) {
      perror("[ERROR] Cannot connect to target");
      close(sock);
      return (-1);
    }
  ct = 0;
  while (LOOP) { /* Value changed with SIGINT only */
    /* First check if total number of requests to send has been reached (-t) */
    if (settings->total > 0 && ct >= settings->total)
      break ;
    /* No return inside loop, need to reach the end of the function to free */
    size = rand() % (settings->max_size - settings->min_size + 1) + settings->min_size;
    if ((packet = malloc(size + 1)) == NULL) {
      ret = -1;
      ERROR("Cannot allocate random packet.");
      break ;
    }
    random_bytes(packet, size);
    insert_locks(packet, size, settings);
    insert_length(packet, size, settings);
    if (STEP) {
      printf("[INFO] About to send %3u bytes: ", size);
      print_bytes(packet, size);
      printf("Press enter to continue.\n");
      getchar();
    }
    if (sendto(sock, packet, size, 0, (struct sockaddr*)&addr,
	       (socklen_t)sizeof(struct sockaddr_in)) < 0) {
      ret = -1;
      perror("[ERROR] Cannot send packet to target");
      /* TCP: We don't want to kill the fuzzer, so we start again. */
      /* Too many sockets involved, that's why we wait. */
      usleep(settings->delay * 1000 + 1000);
      fuzz(settings);
      break ;
    }
    /* Output and throughput control */
    if (!STEP)
      printf("[LFC] %u packets sent.\r", ct);
    free(packet);
    ct += 1;
    usleep(settings->delay * 1000); /* We want milliseconds */
  }
  close(sock);
  return (ret);
}

/*****************************************************************************/
/* Cleaning before exit                                                      */
/*****************************************************************************/

void megafree(args_t *settings) {
  for (unsigned int i = 0; i < settings->locks_nb; i++) {
    if (settings->locks[i] != NULL) {
      if (settings->locks[i]->bytes != NULL)
        free(settings->locks[i]->bytes);
      free(settings->locks[i]);
    }
  }
}

/*****************************************************************************/
/* Run                                                                       */
/*****************************************************************************/

int main(int ac, char **av) {
  args_t settings;

  if (ac <= 1) {
    ERROR("Le fuzzer con expects at least one argument.");
    printf(USAGE);
    return (-1);
  }
  if (set_args(&settings, ac, av) < 0) {
    megafree(&settings);
    return (-1);
  }
  srand(time(0));
  signal(SIGINT, sigint_handler);
  settings_verbose(&settings);
  fuzz(&settings);
  megafree(&settings);
  return (0);
}
