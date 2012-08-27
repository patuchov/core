#include "findhub.h"

bool isIPv6(const char *address)
{
    if (strchr(address, ':') == NULL)
        return false;

    return true;
}

void client_callback(AvahiClient *c, AvahiClientState state, void *userdata)
{
    assert(c);

    if (state == AVAHI_CLIENT_FAILURE)
    {
        fprintf(stderr, "Server connection failuer: %s\n", avahi_strerror(avahi_client_errno(c)));
        avahi_simple_poll_quit(spoll);
    }
}

void browse_callback(AvahiServiceBrowser *b,
                     AvahiIfIndex interface,
                     AvahiProtocol protocol,
                     AvahiBrowserEvent event,
                     const char *name,
                     const char *type,
                     const char *domain,
                     AVAHI_GCC_UNUSED AvahiLookupResultFlags flags,
                     void *userdata)
{
    AvahiClient *c = userdata;
    assert(b);

    switch (event)
    {
    case AVAHI_BROWSER_FAILURE:
        fprintf(stderr, "Error: %s\n", avahi_strerror(avahi_client_errno(avahi_service_browser_get_client(b))));
        avahi_simple_poll_quit(spoll);
        return;

    case AVAHI_BROWSER_NEW:
        if (!(avahi_service_resolver_new(c, interface, protocol, name ,type, domain, AVAHI_PROTO_UNSPEC, 0, resolve_callback, c)))
            fprintf(stderr, "Failed to resolve service '%s': %s\n", name, avahi_strerror(avahi_client_errno(c)));
        break;

    case AVAHI_BROWSER_REMOVE:
        break;

    case AVAHI_BROWSER_ALL_FOR_NOW:
        avahi_simple_poll_quit(spoll);
        break;

    case AVAHI_BROWSER_CACHE_EXHAUSTED:
        break;
    }
}

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
                      AVAHI_GCC_UNUSED void* userdata)
{
    assert(r);

    switch (event)
    {
    case AVAHI_RESOLVER_FAILURE:
        fprintf(stderr, "(Resolver) Failed to resolve service '%s' of type '%s' in domain '%s': %s\n", name, type, domain, avahi_strerror(avahi_client_errno(avahi_service_resolver_get_client(r))));
        break;

    case AVAHI_RESOLVER_FOUND:
        {
        char a[AVAHI_ADDRESS_STR_MAX];

        avahi_address_snprint(a, sizeof(a), address);

        if (!isIPv6(a))
        {
            AddHost(host_name, a, port);
            ++hubcount;
        }
    }
    }
    
    avahi_service_resolver_free(r);
}

void ListHubs()
{
    fprintf(stderr, "Looking for hubs in local network\n");
    AvahiClient *client = NULL;
    AvahiServiceBrowser *sb = NULL;
    int error;
    int ret = 1;

    spoll = NULL;
    list = NULL;
    hubcount = 0;

    if (!(spoll = avahi_simple_poll_new()))
    {
        fprintf(stderr, "Failed to create simple poll object.\n");
        goto fail;
    }

    client = avahi_client_new(avahi_simple_poll_get(spoll), 0, client_callback, NULL, &error);

    if (!client)
    {
        fprintf(stderr, "Failed to create client: %s\n", avahi_strerror(error));
        goto fail;
    }

    if (!(sb = avahi_service_browser_new(client, AVAHI_IF_UNSPEC, AVAHI_PROTO_UNSPEC, "_cfenginehub._tcp", NULL, 0, browse_callback, client)))
    {
        fprintf(stderr, "Failed to create service browser: %s\n", avahi_strerror(avahi_client_errno(client)));
        goto fail;
    }

    avahi_simple_poll_loop(spoll);

    ret = 0;

fail:

    if (sb)
        avahi_service_browser_free(sb);

    if (client)
        avahi_client_free(client);

    if (spoll)
        avahi_simple_poll_free(spoll);

}

int AddHost(const char *hostname, const char *address, uint16_t port)
{
    HostProperties *HP = calloc(1, sizeof(HostProperties));

    strncpy(HP->Hostname, hostname, 4095);
    strncpy(HP->IPAddress, address, 4095);
    HP->Port=port;

    Hosts *tmp = calloc(1, sizeof(HostProperties));

    tmp->HS = HP;
    tmp->next = list;
    list = tmp;

    return 0;
}

void PrintList()
{
    Hosts *tmp = list;
    printf("\n\n===============================\n");
    int i = 1;
    while (tmp != NULL)
    {
        printf("%d. Host %s with IP: %s\n", 
                i++, 
                tmp->HS->Hostname,
                tmp->HS->IPAddress);
        printf("===============================\n");
        tmp = tmp->next;
    }
    printf("\n\n");
}

void CleanUpList()
{
    Hosts *tmp = NULL;
    
    while (list != NULL)
    {
        free(list->HS);
        tmp = list;
        list = list->next;
        free(tmp);
    }

    free(list);
}
