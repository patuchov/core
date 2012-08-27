#ifndef FINDHUB_PRIV_H
#define FINDHUB_PRIV_H

#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>
#include <stdbool.h>

#include <avahi-client/client.h>
#include <avahi-client/lookup.h>

#include <avahi-common/simple-watch.h>
#include <avahi-common/malloc.h>
#include <avahi-common/error.h>
#include <avahi-common/address.h>

AvahiSimplePoll *spoll;

struct HostProperties_
{
    char Hostname[4096];
    char IPAddress[4096];
    uint16_t Port;
};

typedef struct HostProperties_ HostProperties;

struct Hosts_
{
    HostProperties *HS;
    struct Hosts_ *next;
};

typedef struct Hosts_ Hosts;

int hubcount;

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
                      AVAHI_GCC_UNUSED void* userdata);

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
int AddHost(const char *hostname, const char *address, uint16_t port);
void PrintList();
void CleanUpList();

#endif // FINDHUB_PRIV_H
