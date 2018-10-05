#include "hook.h"
#include "logger.h"
#include "tools.h"
#include "dhcp_packet.h"

#include <errno.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>

#define ENV_DATA_MAX 16384ull
#define ENV_PTR_MAX 1024ull
#define ENV_LEN_NAME_MAX 64ull
#define ENV_LEN_VALUE_MAX 512ull

static void hook_put_env(char* data_start, char ** data_next, char** ptr_start, char*** ptr_next, const char * name, const char* value) {
    size_t name_len = strnlen(name, ENV_LEN_NAME_MAX);
    size_t value_len = strnlen(value, ENV_LEN_VALUE_MAX);

    if((size_t)(*data_next - data_start) <= ENV_DATA_MAX - 2ull - name_len - value_len) {
        return;
    }

    if((size_t)(*ptr_next - ptr_start) <= ENV_PTR_MAX - 1ull) {
        return;
    }

    *(*ptr_next)++ = *data_next;
    size_t env_size = snprintf(*data_next, ENV_DATA_MAX - (*data_next - data_start), "%s=%s", name, value);
    *data_next += env_size + 1;
}

typedef void (* hook_decode_option_proc)(uint8_t* option, uint8_t optionlen, char* dest);

struct hook_decode_option_handler_info {
    hook_decode_option_proc handler;
    uint8_t* option_list;
};

typedef struct hook_decode_option_handler_info hook_decode_option_handler_info;

uint8_t hook_decode_optionlist_ipv4[] = {
  1,	// Subnet Mask
  3,	// Routers
  4,	// Time Servers
  5,	// IEN 116 Name Servers
  6,	// Domain Name System Servers
  7,	// MIT-LCS UDP Log Servers
  8,	// Fortune Cookie Servers
  9,	// LPR Servers
  10,	// Impress Servers
  11,	// Resource Location Servers
  16,	// Swap Server
  21,	// Policy Filter Option
  28,	// Broadcast Address
  32,	// Router Solicitation Address
  33,	// Static Routes
  41,	// Network Information Servers
  42,	// NTP Servers
  44,	// NetBIOS Name Servers
  45,	// NetBIOS Datagram Distribution Servers
  48,	// X11 Font Servers
  49,	// X11 Display Manager Servers
  50,	// Client Req IP Address
  54,	// DHCP Server ID/Address
  65,	// NIS+ Servers
  68,	// Mobile IP Home Agent Servers
  69,	// SMTP Servers
  70,	// POP3 Servers
  71,	// NNTP Servers
  72,	// WWW Servers
  73,	// Finger Servers
  74,	// IRC Servers
  75,	// StreetTalk Servers
  76,	// StreetTalk Directory Assistence Servers
  0	// END OF LIST
};
static void hook_decode_option_ipv4(uint8_t* option, uint8_t option_len, char* dest) {
    if(!dest) {
        return;
    }

    char tmp[INET_ADDRSTRLEN] = { 0 };

    while(option_len >= 4) {
        if(!inet_ntop(AF_INET, option, &tmp[0], INET_ADDRSTRLEN)) {
            *dest = 0;
            return;
        }

        strncat(dest, tmp, ENV_LEN_VALUE_MAX - strlen(dest) - 1);

        option += 4;
        option_len -= 4;

        if(option_len >= 4) {
            strncat(dest, ",", ENV_LEN_VALUE_MAX - strlen(dest) - 1);
        }
    }
}

uint8_t hook_decode_optionlist_string[] = {
  12,	// Host Name
  14,	// Crash Dump File
  15,	// Domain Name
  17,	// Root Path
  18,	// Extensions Path
  40,	// Network Information Service Domain
  56,	// Server Error Message
  64,	// NIS+ domain
  66,	// TFTP Server Name
  67,	// TFTP Boot File Name
  81,	// Client FQDN
  0	// END OF LIST
};
static void hook_decode_option_string(uint8_t* option, uint8_t option_len, char* dest) {
    for( ; option_len--; option++, dest++) {
        if(
            (*option >= 'A' && *option <= 'Z') ||
            (*option >= 'a' && *option <= 'z') ||
            (*option >= '0' && *option <= '9') ||
            (*option == '.') ||
            (*option == ':') ||
            (*option == '-') ||
            (*option == '/') ||
            (*option == '_')
        ) {
            *dest = *option;
        } else {
            *dest = '_';
        }
    }

    *dest = 0;
}

uint8_t hook_decode_optionlist_int8[] = {
  19,	// IP Forwarding
  20,	// Non-local Source Routing
  23,	// IP Default TTL
  27,	// All Subnets are Local
  29,	// Perform Mask Discovery
  30,	// Mask Supplier Option
  31,	// Perform Router Discovery
  34,	// Trailer Encapsulation
  36,	// Ethernet Encapsulation
  37,	// TCP Default TTL
  39,	// TCP Keepalive Garbage
  46,	// NetBIOS Node Type
  52,	// DHCP Option Overload
  53,	// DHCP Message Type
  55,	// DHCP Option Request List
  0	// END OF LIST
};
static void hook_decode_option_int8(uint8_t* option, uint8_t option_len, char* dest) {
  *dest = 0;

  if(!option || !option_len) {
    return;
  }

  if(option_len > ENV_LEN_VALUE_MAX / 4ull) {
    option_len = ENV_LEN_VALUE_MAX / 4ull;
  }

  while(option_len) {
    snprintf(dest + strlen(dest), ENV_LEN_VALUE_MAX - strlen(dest), "%u", (uint32_t)*option);

    option_len--;

    if(option_len) {
      strcat(dest, ",");
    }
  }
}

uint8_t hook_decode_optionlist_int16[] = {
  13,	// Boot Image Size (512 Byte Sectors)
  22,	// Maximum Datagram Reassembly Size
  25,	// Path MTU Plateau Table Size
  26,	// Interface MTU Size
  57,	// DHCP Maximum Message Size
  0	// END OF LIST
};
static void hook_decode_option_int16(uint8_t* option, uint8_t option_len, char* dest) {
  *dest = 0;

  if(!option || option_len < 2) {
    return;
  }

  if(option_len > ENV_LEN_VALUE_MAX / 8ull) {
    option_len = ENV_LEN_VALUE_MAX / 8ull;
  }

  while(option_len >= 2) {
    snprintf(dest + strlen(dest), ENV_LEN_VALUE_MAX - strlen(dest), "%u", option[0] * 256u + option[1]);

    option_len -= 2;

    if(option_len >= 2) {
      strcat(dest, ",");
    }
  }
}

uint8_t hook_decode_optionlist_int32[] = {
  2,	// UTC offset (seconds)
  24,	// Path MTU Aging Timeout
  35,	// ARP Cache Timeout
  38,	// TCP Keepalive Timeout
  51,	// DHCP Lease Timeout
  58,	// DHCP Renewal (T1) Timeout
  59,	// DHCP Rebind (T2) Timeout
  0	// END OF LIST
};
static void hook_decode_option_int32(uint8_t* option, uint8_t option_len, char* dest) {
  *dest = 0;

  if(!option || option_len < 4) {
    return;
  }

  if(option_len > ENV_LEN_VALUE_MAX / 12ull) {
    option_len = ENV_LEN_VALUE_MAX / 12ull;
  }

  while(option_len >= 4) {
    snprintf(dest + strlen(dest), ENV_LEN_VALUE_MAX - strlen(dest), "%u", ntohl(*(int32_t *)option));

    option_len -= 4;

    if(option_len >= 4) {
      strcat(dest, ",");
    }
  }
}

static hook_decode_option_handler_info const hook_option_decoders[] = {
    { .handler = hook_decode_option_ipv4, .option_list = hook_decode_optionlist_ipv4 },
    { .handler = hook_decode_option_string, .option_list = hook_decode_optionlist_string },
    { .handler = hook_decode_option_int8, .option_list = hook_decode_optionlist_int8 },
    { .handler = hook_decode_option_int16, .option_list = hook_decode_optionlist_int16 },
    { .handler = hook_decode_option_int32, .option_list = hook_decode_optionlist_int32 },
    { .handler = NULL, .option_list = NULL }
};

void hook(uint8_t type, struct in_addr* address, uint8_t* chaddr, ddhcp_config* config, void* args) {
#if LOG_LEVEL_LIMIT >= LOG_DEBUG
  char* hwaddr = hwaddr2c(chaddr);
  DEBUG("hook(type:%i,addr:%s,chaddr:%s,config)\n", type, inet_ntoa(*address), hwaddr);
  free(hwaddr);
#endif

  if (!config->hook_command) {
    DEBUG("hook(...): No hook command set\n");
    return;
  }

  int pid;

  char* action = NULL;

  dhcp_packet* packet = NULL;

  switch (type) {
  case HOOK_LEASE:
    action = (char*)"lease";
    packet = (dhcp_packet*)args;
    break;

  case HOOK_RELEASE:
    action = (char*)"release";
    packet = (dhcp_packet*)args;
    break;

  default:
    break;
  }

  if (!action) {
    DEBUG("hook(...): unknown hook type: %i\n", type);
    return;
  }

  pid = fork();

  if (pid < 0) {
    // TODO: Include errno from fork
    FATAL("hook(...): Failed to fork() for hook command execution (errno: %i).\n", pid);
    return;
  }

  if (pid != 0) {
    //Nothing to do as the parent
    return;
  }

  char* env_data = calloc(ENV_DATA_MAX, sizeof(char));
  if(!env_data) {
    FATAL("hook(...): Failed to allocate environment data block for hook command execution (errno: %i).\n", -ENOMEM);
    return;
  }

  char** env_ptr = calloc(ENV_PTR_MAX, sizeof(char *));
  if(!env_ptr) {
    free(env_data);
    FATAL("hook(...): Failed to allocate environment pointer block for hook command execution (errno: %i).\n", -ENOMEM);
    return;
  }

  // This holds where the next environment variable string is put
  char* env_data_next = env_data;

  // This holds where the next environment variable ptr is put
  char** env_ptr_next = env_ptr;

  // Okay, let's build our environment for the client
  {
    char name[ENV_LEN_NAME_MAX] = { 0 };
    char value[ENV_LEN_VALUE_MAX] = { 0 };

    hook_put_env(env_data, &env_data_next, env_ptr, &env_ptr_next, "DHCP_ACTION", action);

    snprintf(value, ENV_LEN_VALUE_MAX, "%08X", packet->xid);
    hook_put_env(env_data, &env_data_next, env_ptr, &env_ptr_next, "DHCP_TXID", value);

    if(packet) {
      dhcp_option* option = packet->options;
      for(size_t idx = 0; idx < packet->options_len; idx++, option++) {
        if(0 == option->code || 255 == option->code) {
          continue;
        }

        snprintf(name, sizeof(name), "DHCP_OPTION_%02X", option->code);

        char* value_ptr = &value[0];
        *value_ptr = 0;

        if(option->payload && option->len) {
          uint8_t* payload_ptr = option->payload;
          for(size_t len = option->len; len; len--, value_ptr += 2, payload_ptr++) {
            snprintf(value_ptr, ENV_LEN_VALUE_MAX - (value_ptr - &value[0]), "%02X", *payload_ptr);
          }
        }

        hook_put_env(env_data, &env_data_next, env_ptr, &env_ptr_next, name, value);

        for(
          hook_decode_option_handler_info const * decoder_info = &hook_option_decoders[0];
          decoder_info->handler && decoder_info->option_list;
          decoder_info++) {

          uint8_t* decoder_code = decoder_info->option_list;
          while(decoder_code && *decoder_code) {
            if(*decoder_code != option->code) {
              decoder_code++;
              continue;
            }

            decoder_code = NULL;

            value[0] = 0;

            decoder_info->handler(option->payload, option->len, &value[0]);

            snprintf(name, sizeof(name), "DHCP_VALUE_%02X", option->code);
            hook_put_env(env_data, &env_data_next, env_ptr, &env_ptr_next, name, value);
          }

          if(!decoder_code) {
            break;
          }
        }
      }
    }

  }

  // Ensure the environment is terminated properly
  *env_data_next = 0;
  *env_ptr_next = NULL;

  int err = execle(
    // Binary to execute
    "/bin/sh",

    // Arguments to pass
    "/bin/sh", //Be pedantic about executing /bin/sh
    "-e", // Terminate on error return
    "--", // Terminate argument parsing
    config->hook_command, // Our actual command to run
    action, // The action we notify about
    inet_ntoa(*address), // The affected IP address
    hwaddr2c(chaddr), // The affected MAC address
    (char*) NULL, // End of command line
    env_ptr //Pointer to array of environment variables
  );

  free(env_ptr);
  free(env_data);

  if (err < 0) {
    // TODO: Logging from the child should be synchronized
    FATAL("hook(...): Command could not be executed (errno: %i).\n", err);
  }

  exit(1);
}

void cleanup_process_table(int signum)
{
  UNUSED(signum);
  DEBUG("cleanup_process_table(...): Got signal %i\n", signum);
  wait(NULL);
}

void hook_init() {
  signal(SIGCHLD, cleanup_process_table);
}
