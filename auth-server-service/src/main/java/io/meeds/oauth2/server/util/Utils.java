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

import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.URI;
import java.net.UnknownHostException;

public class Utils {

  private Utils() {
    // Utils Class
  }

  public static URI validateUrl(String raw) throws UnknownHostException { // NOSONAR
    URI uri = URI.create(raw).normalize();

    if (!"https".equalsIgnoreCase(uri.getScheme())) {
      throw new IllegalArgumentException("Only https logo URLs are allowed");
    }
    String host = uri.getHost();
    if (host == null || host.isBlank()) {
      throw new IllegalArgumentException("Missing host");
    }
    if (uri.getUserInfo() != null) {
      throw new IllegalArgumentException("User info is not allowed");
    }
    if (uri.getFragment() != null) {
      throw new IllegalArgumentException("Fragments are not allowed");
    }

    int port = uri.getPort();
    if (port != -1 && port != 443) {
      throw new IllegalArgumentException("Port not allowed");
    }

    String s = uri.toASCIIString();
    if (s.length() > 2048) {
      throw new IllegalArgumentException("URL too long");
    }
    InetAddress[] addresses = InetAddress.getAllByName(host);
    if (addresses.length == 0) {
      throw new IllegalArgumentException("Host did not resolve");
    }
    for (InetAddress addr : addresses) {
      if (addr.isAnyLocalAddress()
          || addr.isLoopbackAddress()
          || addr.isLinkLocalAddress()
          || addr.isSiteLocalAddress()
          || addr.isMulticastAddress()) {
        throw new IllegalArgumentException("Host resolves to a non-public address");
      }
      if (addr instanceof Inet6Address) {
        byte first = addr.getAddress()[0];
        if ((first & (byte) 0xfe) == (byte) 0xfc) {
          throw new IllegalArgumentException("Host resolves to a non-public IPv6 address");
        }
      }
    }
    return uri;
  }
}
