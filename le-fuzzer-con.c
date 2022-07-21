#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdbool.h>
#include <getopt.h>
#include <ctype.h>
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
  "                [-b locked_bits] host (--help)" \
  "\n"
#define HELP "" \
  "Another dumb network fuzzer, but not the worst one." \
  "\n\n" \
  "Arguments:\n" \
  "\n"

#define MIN_SIZE 0
#define MAX_SIZE 4000 /* Arbitrary */
#define DELIM ";"

#define LOCK_REGEX "^([0-9]+):([0-9a-fA-F\\x]+)$"
#define MAX_LOCKS 128 /* Arbitrary */

#define TARGET_REGEX "^(tcp|udp)://([0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+):([0-9]+)$"

/* Global */
bool VERBOSE = false;
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
  unsigned int position;
  size_t length;
  char *bytes;
} lock_t;

typedef struct args {
  target_t target;
  unsigned int min_size;
  unsigned int max_size;
  lock_t *locks[MAX_LOCKS];
  unsigned int locks_nb;
} args_t;

/*****************************************************************************/
/* Print macros and functions                                                */
/*****************************************************************************/

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

int str_to_bytes(char *arg, size_t length, char *bytes) {
  unsigned int ct;
  char *str;

  if ((str = malloc(length + 1)) == NULL)
    return (ERROR("Could not allocate memory for lock."));
  memset(str, 0, length + 1);
  /* Removing delimiter because it's an easier solution... */
  ct = 0;
  for (unsigned int i = 0; i < length; i++) {
    if (arg[i] != '\\' && arg[i] != 'x') {
      str[ct] = arg[i];
      ct++;
    }
  }
  str[ct] = 0;
  /* Storing it to bytes using scanf */
  ct = 0;
  for (unsigned int i = 0; i <= strlen(str); i += 2) {
    char buf[3] = { str[i], str[i+1], 0 };
    bytes[ct] = strtol(buf, NULL, 16);
    ct++;
  }
  free(str);
  return (ct - 1);
}

/*****************************************************************************/
/* Signals handling                                                          */
/*****************************************************************************/

void sigint_handler(int sig_num)
{
  /* We use a global variable that will properly exit the fuzzing loop. */
  printf("\nExiting.\n");
  LOOP = false;
}

/*****************************************************************************/
/* Settings initialization                                                   */
/*****************************************************************************/

/* Store target information into a target_t structure (in settings_t).
Target argument format is "proto://ip:port" where :
- proto: either "tcp" or "udp"
- ip; IPv4 address ("A.B.C.D")
- port: Port number (1-65535)
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

/* Store one lock information into a lock_t structure (in settings_t).
Isolated lock argument format is "position:content" where :
- position: position in the final packet where content should be placed
- content: byte array with format \x00\x00\x00..."
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
  if ((length = str_to_bytes(&arg[content.rm_so],
			     content.rm_eo - content.rm_so, bytes)) < 0)
    return (-1);
  settings->locks[settings->locks_nb]->bytes = bytes;
  settings->locks[settings->locks_nb]->length = length;
  settings->locks_nb++;
  if (settings->locks_nb >= MAX_LOCKS)
    return (ERROR("Maximum number of locks exceeded."));
  return (0);
}

/* Parse the lock argument to extract information about locks.
Lock argument format is "lock1;lock2;..." where each lock contains the
location and content that will be fixed in a packet with format
"position:content"
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
    { "min", required_argument, NULL, 'm' },
    { "max", required_argument, NULL, 'n' },
    { "lock", required_argument, NULL, 'l' },
    { "bitlock", required_argument, NULL, 'b' },
    { 0 }
  };
  unsigned char arg;

  /* Init */
  settings->target = (target_t){ 0 };
  settings->min_size = MIN_SIZE;
  settings->max_size = MAX_SIZE;
  settings->locks_nb = 0;
  memset(settings->locks, 0, sizeof(void*) * MAX_LOCKS);
  /* Parsing */
  while ((arg = getopt_long(ac, av, "hvm:n:l:b:", longopts, 0)) > -1 && arg != 255) {
    if (arg == 'h') { /* Print help and exit */
      printf(HELP);
      break ;
    }
    else if (arg == 'v') { /* Enable verbose mode */
      VERBOSE = true; /* Global */
      VPRINT("Verbose mode enabled.");
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
/* Fuzz                                                                      */
/*****************************************************************************/

void random_bytes(char *packet, unsigned int size) {
  for (unsigned int i = 0; i < size; i++)
    packet[i] = rand();
}

void insert_locks(char *packet, unsigned int size, args_t *settings) {
  unsigned int pos;
  
  for (unsigned int i = 0; i < settings->locks_nb; i++) {
    if (settings->locks[i]->position + settings->locks[i]->length < size) {
      pos = settings->locks[i]->position;
      for (unsigned int j = 0; j < settings->locks[i]->length; j++) {
	packet[pos++] = settings->locks[i]->bytes[j];
      }
    }
  }
}

int fuzz(args_t *settings) {
  unsigned int size;
  char *packet;

  LOOP = true;
  for (unsigned int i = 0; i < 10; i++) { /* Will be infinite loop :) */
    if (LOOP == false)
      break ;
    size = rand() % (settings->max_size - settings->min_size + 1) + settings->min_size;
    if ((packet = malloc(size + 1)) == NULL)
      return (ERROR("Cannot allocate random packet."));
    random_bytes(packet, size);
    insert_locks(packet, size, settings);
    if (VERBOSE) {
      printf("[INFO] Sending %3u bytes: ", size);
      print_bytes(packet, size);
    }
    free(packet);
  }
  return (0);
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
