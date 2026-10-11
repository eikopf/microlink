#pragma once
#include "arch.h"
struct pbuf;
struct netif {
    err_t (*input)(struct pbuf *, struct netif *);
    int link_up;
};
