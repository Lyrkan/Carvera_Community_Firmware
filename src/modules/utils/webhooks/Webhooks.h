#ifndef WEBHOOKS_H
#define WEBHOOKS_H

/*
 * M8266 socket link reserved for outbound webhook TCP client.
 * WifiProvider uses links 0 (TCP server) and 1 (UDP); receive_wifi_data discards traffic on this link.
 */
#define WEBHOOK_TCP_LINK_NO 2u

#include "Module.h"
#include <stdint.h>

class Webhooks : public Module {
public:
    Webhooks();

    void on_module_loaded();
    void on_idle(void *argument);

private:
    bool sta_wifi_ready();
    bool parse_and_split_url();
    bool looks_like_ipv4(const char *host) const;
    bool resolve_host_ip();
    void enqueue_state_change(uint8_t prev, uint8_t now);
    void pump_connection();

    bool enabled;
    bool debug;
    bool use_tls;
    uint16_t min_interval_ms;
    uint32_t last_success_us;

    char url_buf[192];
    char header_name[40];
    char header_value[96];

    char http_host[128];
    char resolved_ip[16];
    uint16_t http_port;
    char http_path[160];

    uint8_t last_state;
    bool have_last_state;

    struct Job {
        uint8_t prev_state;
        uint8_t new_state;
        uint8_t halt_reason;
    };

    static const int QDEPTH = 8;
    Job queue[QDEPTH];
    int q_head;
    int q_tail;

    Job active;
    bool active_valid;

    enum Phase : uint8_t {
        PHASE_IDLE = 0,
        PHASE_CONNECT,
        PHASE_SEND,
        PHASE_RECV,
        PHASE_CLEANUP
    };
    Phase phase;

    uint8_t tx_buf[1460];
    uint16_t tx_len;
    uint16_t tx_sent;
    uint8_t recv_acc[512];
    uint16_t recv_len;
    uint8_t recv_rounds;
};

#endif
