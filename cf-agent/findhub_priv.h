#ifndef FINDHUB_PRIV_H
#define FINDHUB_PRIV_H

#include "load_avahi.h"
#include "list.h"

AvahiSimplePoll *spoll;

struct HostProperties_
{
    char Hostname[4096];
    char IPAddress[AVAHI_ADDRESS_STR_MAX];
    uint16_t Port;
};

typedef struct HostProperties_ HostProperties;

struct Hosts_
{
    HostProperties *HP;
    struct Hosts_ *next;
};

typedef struct Hosts_ Hosts;


void resolve_callback(AvahiServiceResolver *r,
                      AVAHI_GCC_UNUSED AvahiIfIndex interface,
                      AVAHI_GCC_UNUSED AvahiProtocol protocol,
                      AvahiResolverEvent event,
                      const char *name,
                      const char *type,
                      const char *domain,
                      const char *host_name,
                      const AvahiAddress *address,
                      uint16_t port,
                      AvahiStringList *txt,
                      AvahiLookupFlags flags,
                      AVAHI_GCC_UNUSED void* userdata
                      );
void browse_callback(AvahiServiceBrowser *b,
                     AvahiIfIndex interface,
                     AvahiProtocol protocol,
                     AvahiBrowserEvent event,
                     const char *name,
                     const char *type,
                     const char *domain,
                     AVAHI_GCC_UNUSED AvahiLookupResultFlags flags,
                     void *userdata);
void client_callback(AvahiClient *c,
                     AvahiClientState state,
                     AVAHI_GCC_UNUSED void *userdata);
bool isIPv6(const char *address);
void AddHost(const char *hostname, const char *IPAddress, uint16_t port);
void CleanupList(void);
void PrintList(List *list);
int CountHubs(void);
#endif // FINDHUB_PRIV_H