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
