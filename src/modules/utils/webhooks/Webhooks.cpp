#include "Webhooks.h"

#include "Kernel.h"
#include "Config.h"
#include "ConfigValue.h"
#include "checksumm.h"
#include "mbed.h"

#include "libs/StreamOutputPool.h"

#include "brd_cfg.h"
#include "modules/utils/wifi/M8266HostIf.h"
#include "modules/utils/wifi/M8266WIFIDrv.h"
#include <cstdio>
#include <cstring>

#define webhook_checksum CHECKSUM("webhook")
#define webhook_enable_checksum CHECKSUM("enable")
#define webhook_url_checksum CHECKSUM("url")
#define webhook_header_name_checksum CHECKSUM("header_name")
#define webhook_header_value_checksum CHECKSUM("header_value")
#define webhook_min_interval_ms_checksum CHECKSUM("min_interval_ms")
#define webhook_debug_checksum CHECKSUM("debug")

#define WEBHOOK_RECV_TIMEOUT_MS 50
#define WEBHOOK_MAX_RECV_ROUNDS 80

static const char *state_name(uint8_t s)
{
    switch (s) {
        case IDLE:
            return "idle";
        case RUN:
            return "run";
        case HOLD:
            return "hold";
        case HOME:
            return "home";
        case ALARM:
            return "alarm";
        case SLEEP:
            return "sleep";
        case SUSPEND:
            return "suspend";
        case WAIT:
            return "wait";
        case TOOL:
            return "tool";
        default:
            return "unknown";
    }
}

Webhooks::Webhooks()
    : enabled(false)
    , debug(false)
    , use_tls(false)
    , min_interval_ms(0)
    , last_success_us(0)
    , http_port(80)
    , last_state(0)
    , have_last_state(false)
    , q_head(0)
    , q_tail(0)
    , active_valid(false)
    , phase(PHASE_IDLE)
    , tx_len(0)
    , tx_sent(0)
    , recv_len(0)
    , recv_rounds(0)
{
    url_buf[0] = '\0';
    header_name[0] = '\0';
    header_value[0] = '\0';
    http_host[0] = '\0';
    resolved_ip[0] = '\0';
    http_path[0] = '/';
    http_path[1] = '\0';
}

void Webhooks::on_module_loaded()
{
    enabled = THEKERNEL->config->value(webhook_checksum, webhook_enable_checksum)->by_default(false)->as_bool();
    if (!enabled) {
        delete this;
        return;
    }

    debug = THEKERNEL->config->value(webhook_checksum, webhook_debug_checksum)->by_default(false)->as_bool();
    min_interval_ms = (uint16_t) THEKERNEL->config->value(webhook_checksum, webhook_min_interval_ms_checksum)->by_default(0)->as_int();

    std::string u = THEKERNEL->config->value(webhook_checksum, webhook_url_checksum)->by_default("")->as_string();
    strncpy(url_buf, u.c_str(), sizeof(url_buf) - 1);
    url_buf[sizeof(url_buf) - 1] = '\0';

    std::string hn = THEKERNEL->config->value(webhook_checksum, webhook_header_name_checksum)->by_default("")->as_string();
    strncpy(header_name, hn.c_str(), sizeof(header_name) - 1);
    header_name[sizeof(header_name) - 1] = '\0';

    std::string hv = THEKERNEL->config->value(webhook_checksum, webhook_header_value_checksum)->by_default("")->as_string();
    strncpy(header_value, hv.c_str(), sizeof(header_value) - 1);
    header_value[sizeof(header_value) - 1] = '\0';

    if (url_buf[0] == '\0') {
        if (debug) {
            THEKERNEL->streams->printf("webhook: disabled (empty url)\n");
        }
        delete this;
        return;
    }

    register_for_event(ON_IDLE);
}

bool Webhooks::sta_wifi_ready()
{
    u8 connection_status = 0;
    u16 status = 0;
    if (!M8266WIFI_SPI_Get_STA_Connection_Status(&connection_status, &status)) {
        return false;
    }
    return connection_status == 5;
}

bool Webhooks::looks_like_ipv4(const char *host) const
{
    unsigned a = 0, b = 0, c = 0, d = 0;
    if (sscanf(host, "%u.%u.%u.%u", &a, &b, &c, &d) != 4) {
        return false;
    }
    return a <= 255 && b <= 255 && c <= 255 && d <= 255;
}

bool Webhooks::parse_and_split_url()
{
    const char *url = url_buf;
    use_tls = false;
    http_port = 80;
    http_host[0] = '\0';
    http_path[0] = '/';
    http_path[1] = '\0';

    const char *host_start = nullptr;
    if (strncmp(url, "https://", 8) == 0) {
        use_tls = true;
        http_port = 443;
        host_start = url + 8;
    } else if (strncmp(url, "http://", 7) == 0) {
        host_start = url + 7;
    } else {
        if (debug) {
            THEKERNEL->streams->printf("webhook: URL must start with http:// or https://\n");
        }
        return false;
    }
    const char *path_sep = strchr(host_start, '/');

    char host_port_buf[128];
    size_t hp_len = path_sep ? (size_t)(path_sep - host_start) : strlen(host_start);
    if (hp_len == 0 || hp_len >= sizeof(host_port_buf)) {
        return false;
    }

    memcpy(host_port_buf, host_start, hp_len);
    host_port_buf[hp_len] = '\0';

    char *colon = strrchr(host_port_buf, ':');
    if (colon != nullptr && colon != host_port_buf) {
        bool digits_only = true;
        for (char *p = colon + 1; *p; p++) {
            if (*p < '0' || *p > '9') {
                digits_only = false;
                break;
            }
        }
        if (digits_only && *(colon + 1) != '\0') {
            http_port = (uint16_t) atoi(colon + 1);
            if (http_port == 0) {
                http_port = use_tls ? 443 : 80;
            }
            *colon = '\0';
        }
    }

    strncpy(http_host, host_port_buf, sizeof(http_host) - 1);
    http_host[sizeof(http_host) - 1] = '\0';

    if (path_sep != nullptr) {
        strncpy(http_path, path_sep, sizeof(http_path) - 1);
        http_path[sizeof(http_path) - 1] = '\0';
        if (http_path[0] == '\0') {
            strncpy(http_path, "/", sizeof(http_path) - 1);
        }
    }

    return http_host[0] != '\0';
}

bool Webhooks::resolve_host_ip()
{
    if (looks_like_ipv4(http_host)) {
        strncpy(resolved_ip, http_host, sizeof(resolved_ip) - 1);
        resolved_ip[sizeof(resolved_ip) - 1] = '\0';
        return true;
    }

    u16 status = 0;
    resolved_ip[0] = '\0';
    char hostname_mut[128];
    strncpy(hostname_mut, http_host, sizeof(hostname_mut) - 1);
    hostname_mut[sizeof(hostname_mut) - 1] = '\0';

    if (!M8266WIFI_SPI_STA_Get_HostIP_by_HostName(resolved_ip, hostname_mut, 8, &status)) {
        if (debug) {
            THEKERNEL->streams->printf("webhook: DNS failed for %s (status=%u)\n", http_host, status);
        }
        return false;
    }
    return resolved_ip[0] != '\0';
}

void Webhooks::enqueue_state_change(uint8_t prev, uint8_t now)
{
    int next_tail = (q_tail + 1) % QDEPTH;
    if (next_tail == q_head) {
        if (debug) {
            THEKERNEL->streams->printf("webhook: queue full, dropping event\n");
        }
        return;
    }

    Job j;
    j.prev_state = prev;
    j.new_state = now;
    j.halt_reason = (now == ALARM) ? THEKERNEL->get_halt_reason() : 0;
    queue[q_tail] = j;
    q_tail = next_tail;
}

void Webhooks::on_idle(void *argument)
{
    (void) argument;

    if (!enabled) {
        return;
    }

    if (THEKERNEL->is_uploading()) {
        return;
    }

    uint8_t st = THEKERNEL->get_state();
    if (!have_last_state) {
        last_state = st;
        have_last_state = true;
    } else if (st != last_state) {
        enqueue_state_change(last_state, st);
        last_state = st;
    }

    pump_connection();
}

void Webhooks::pump_connection()
{
    if (phase == PHASE_IDLE) {
        if (active_valid) {
            return;
        }
        if (q_head == q_tail) {
            return;
        }

        if (min_interval_ms > 0 && last_success_us != 0) {
            uint32_t now = us_ticker_read();
            uint32_t elapsed_us = now - last_success_us;
            if (elapsed_us / 1000U < (uint32_t) min_interval_ms) {
                return;
            }
        }

        active = queue[q_head];
        q_head = (q_head + 1) % QDEPTH;
        active_valid = true;
        phase = PHASE_CONNECT;
        tx_sent = 0;
        recv_len = 0;
        recv_rounds = 0;
        tx_len = 0;
    }

    if (!active_valid) {
        phase = PHASE_IDLE;
        return;
    }

    if (!sta_wifi_ready()) {
        if (debug) {
            THEKERNEL->streams->printf("webhook: STA not connected, skip\n");
        }
        phase = PHASE_CLEANUP;
    }

    u16 status = 0;

    switch (phase) {
        case PHASE_CONNECT: {
            if (!parse_and_split_url()) {
                phase = PHASE_CLEANUP;
                break;
            }
            if (!resolve_host_ip()) {
                phase = PHASE_CLEANUP;
                break;
            }

            M8266WIFI_SPI_Delete_Connection(WEBHOOK_TCP_LINK_NO, &status);

            u8 sock =
                (u8)(SOCKET_TYPE_TCP_CLIENT | (use_tls ? SOCKET_TCP_CLIENT_BITMAP_SSL : 0));
            if (!M8266WIFI_SPI_Setup_Connection(sock, 0, resolved_ip, http_port, WEBHOOK_TCP_LINK_NO, 15, &status)) {
                if (debug) {
                    THEKERNEL->streams->printf("webhook: %s connect failed (status=%u)\n",
                                               use_tls ? "TLS" : "TCP", status);
                }
                phase = PHASE_CLEANUP;
                break;
            }
            phase = PHASE_SEND;
            break;
        }

        case PHASE_SEND: {
            char body[192];
            if (active.new_state == ALARM) {
                snprintf(body, sizeof(body),
                         "{\"event\":\"machine_state\",\"prev\":\"%s\",\"state\":\"%s\",\"halt_reason\":%u}",
                         state_name(active.prev_state), state_name(active.new_state), (unsigned) active.halt_reason);
            } else {
                snprintf(body, sizeof(body), "{\"event\":\"machine_state\",\"prev\":\"%s\",\"state\":\"%s\"}",
                         state_name(active.prev_state), state_name(active.new_state));
            }

            const unsigned body_len = (unsigned) strlen(body);

            int n = snprintf((char *) tx_buf, sizeof(tx_buf),
                             "POST %s HTTP/1.1\r\n"
                             "Host: %s\r\n"
                             "Content-Type: application/json\r\n"
                             "Connection: close\r\n",
                             http_path, http_host);

            if (header_name[0] != '\0' && header_value[0] != '\0') {
                n += snprintf((char *) tx_buf + n, sizeof(tx_buf) - (size_t) n, "%s: %s\r\n", header_name, header_value);
            }

            n += snprintf((char *) tx_buf + n, sizeof(tx_buf) - (size_t) n, "Content-Length: %u\r\n\r\n%s", body_len, body);

            if (n <= 0 || (size_t) n >= sizeof(tx_buf)) {
                if (debug) {
                    THEKERNEL->streams->printf("webhook: request too large\n");
                }
                phase = PHASE_CLEANUP;
                break;
            }

            tx_len = (uint16_t) n;

            u32 sent = M8266WIFI_SPI_Send_BlockData(tx_buf, tx_len, 3000, WEBHOOK_TCP_LINK_NO, nullptr, 0, &status);
            if (sent != tx_len) {
                if (debug) {
                    THEKERNEL->streams->printf("webhook: send incomplete %lu/%u\n", (unsigned long) sent, tx_len);
                }
                phase = PHASE_CLEANUP;
                break;
            }

            recv_len = 0;
            recv_rounds = 0;
            phase = PHASE_RECV;
            break;
        }

        case PHASE_RECV: {
            if (recv_rounds >= WEBHOOK_MAX_RECV_ROUNDS) {
                phase = PHASE_CLEANUP;
                break;
            }

            recv_rounds++;
            u8 link_no = 0;
            u8 chunk_buf[256];
            u16 got = M8266WIFI_SPI_RecvData(chunk_buf, sizeof(chunk_buf), WEBHOOK_RECV_TIMEOUT_MS, &link_no, &status);

            if (link_no == WEBHOOK_TCP_LINK_NO && got > 0) {
                size_t copy = got;
                if (recv_len + copy > sizeof(recv_acc) - 1) {
                    copy = sizeof(recv_acc) - 1 - recv_len;
                }
                if (copy > 0) {
                    memcpy(recv_acc + recv_len, chunk_buf, copy);
                    recv_len += (uint16_t) copy;
                    recv_acc[recv_len] = '\0';
                }

                if (strstr((char *) recv_acc, "\r\n\r\n") != nullptr) {
                    phase = PHASE_CLEANUP;
                }
            }
            break;
        }

        case PHASE_CLEANUP:
        default:
            M8266WIFI_SPI_Delete_Connection(WEBHOOK_TCP_LINK_NO, &status);
            active_valid = false;
            phase = PHASE_IDLE;
            last_success_us = us_ticker_read();
            break;
    }
}
