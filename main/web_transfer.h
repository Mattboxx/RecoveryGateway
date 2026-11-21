/* Bounded background HTTP response streaming.
 * Original implementation, Mattboxx Edition. SPDX-License-Identifier: GPL-3.0-only */
#pragma once

#include "esp_http_server.h"

typedef esp_err_t (*web_transfer_serve_t)(httpd_req_t *req, const void *argument);

/* Called from an authenticated handler. Copies the small argument and
 * admits at most one bulk response across all callers. */
esp_err_t web_transfer_start(httpd_req_t *req, web_transfer_serve_t serve,
                             const void *argument, size_t argument_size);
