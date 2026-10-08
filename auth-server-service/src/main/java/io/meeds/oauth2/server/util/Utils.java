/**
 * This file is part of the Meeds project (https://meeds.io/).
 *
 * Copyright (C) 2020 - 2026 Meeds Association contact@meeds.io
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 3 of the License, or (at your option) any later version.
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 */
package io.meeds.oauth2.server.util;

import java.time.Duration;
import java.util.Set;

import io.meeds.commons.http.SafeFetchPolicy;
import io.meeds.commons.http.SafeFetchPolicyBuilder;

public class Utils {

  public static final String   OFFLINE_ACCESS_SCOPE   = "offline_access";

  /**
   * Most bytes read of a Client ID Metadata Document: a JSON document of a
   * few hundred bytes, far below this bound.
   */
  public static final long     CIMD_MAX_BYTES         = 64L * 1024;

  /** Name of the fetcher of the URLs a client gives, and of its deadline thread. */
  public static final String   URL_FETCHER_NAME       = "auth-server-url-fetcher";

  /** User-Agent of the fetches of the URLs a client gives. */
  public static final String   URL_FETCHER_USER_AGENT = "Meeds-Auth-Server/1.0";

  /** Longest wait for a connection to a URL a client gives. */
  public static final Duration URL_CONNECT_TIMEOUT    = Duration.ofSeconds(3);

  /** Longest wait between two reads of a URL a client gives. */
  public static final Duration URL_READ_TIMEOUT       = Duration.ofSeconds(10);

  /** Longest read of a URL a client gives. */
  public static final Duration URL_TOTAL_TIMEOUT      = Duration.ofSeconds(20);

  private Utils() {
    // Utils Class
  }

  /**
   * The policy under which the server reads a URL a client gives — the Client
   * ID Metadata Document a {@code client_id} names, the logo a client
   * declares: https on port 443, public addresses only, judged by the HTTP
   * client's own resolver at every connection, no redirect followed, the
   * timeouts above.
   *
   * @param maxBytes the most bytes a read takes, the largest of the reads made
   *          under this policy
   * @return the policy's builder, for a test to replace the resolver
   */
  public static SafeFetchPolicyBuilder urlFetchPolicy(long maxBytes) {
    return SafeFetchPolicy.builder()
                          .name(URL_FETCHER_NAME)
                          .userAgent(URL_FETCHER_USER_AGENT)
                          .httpsOnly()
                          .allowedPorts(Set.of(443))
                          .maxRedirects(0)
                          .maxBytes(maxBytes)
                          .connectTimeout(URL_CONNECT_TIMEOUT)
                          .readTimeout(URL_READ_TIMEOUT)
                          .totalTimeout(URL_TOTAL_TIMEOUT);
  }

}
