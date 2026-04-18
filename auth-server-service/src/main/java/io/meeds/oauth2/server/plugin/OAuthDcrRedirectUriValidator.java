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
package io.meeds.oauth2.server.plugin;

import static io.meeds.oauth2.server.util.EntityMapper.*;

import java.net.URI;
import java.util.List;

import org.apache.commons.collections4.CollectionUtils;
import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.stereotype.Component;

import io.meeds.oauth2.server.service.OAuthSettingService;

import lombok.SneakyThrows;

@Component
public class OAuthDcrRedirectUriValidator implements OAuthDcrValidator {

  @Autowired
  private OAuthSettingService oAuthSettingService;

  @Override
  public void validate(RegisteredClient client) {
    if (CollectionUtils.isEmpty(client.getRedirectUris())) {
      throw new IllegalStateException("[DCR] Self Registration Client '%s' rejected. Reason: Only one base Redirect URI is missing".formatted(client.getClientName()));
    } else if (isDcrClient(client)
               && countRedirectBaseUris(client) != 1) {
      throw new IllegalStateException("[DCR] Self Registration Client '%s' rejected. Reason: Only one base Redirect URI is allowed in Open Registration Clients".formatted(client.getClientName()));
    } else if (isDcrClient(client)
               && !client.getRedirectUris()
                         .stream()
                         .allMatch(oAuthSettingService::isAllowedRedicrectUri)) {
      List<String> notAllowedUris = client.getRedirectUris()
                                          .stream()
                                          .filter(u -> !oAuthSettingService.isAllowedRedicrectUri(u))
                                          .toList();
      String rejectedValues = StringUtils.join(notAllowedUris, ',');
      throw new IllegalStateException("[DCR] Self Registration Client '%s' rejected. Reason: Not allowed redirect URI '%s'".formatted(client.getClientName(),
                                                                                                                                      rejectedValues));
    }
  }

  private boolean isDcrClient(RegisteredClient client) {
    return client.getClientSettings().getSetting(CLIENT_IS_CIMD_SETTING) == null
           || (client.getClientSettings().getSetting(CLIENT_IS_DCR_SETTING) != null
               && Boolean.TRUE.equals(client.getClientSettings().getSetting(CLIENT_IS_DCR_SETTING)));
  }

  private long countRedirectBaseUris(RegisteredClient client) {
    return client.getRedirectUris()
                 .stream()
                 .map(this::toBaseUri)
                 .distinct()
                 .count();
  }

  @SneakyThrows
  private String toBaseUri(String urlString) {
    URI uri = new URI(urlString);
    String scheme = uri.getScheme();
    String authority = uri.getAuthority();
    if (scheme == null || authority == null) {
      throw new IllegalStateException("Malformed URL: %s".formatted(urlString));
    }
    return "%s://%s".formatted(scheme.toLowerCase(), authority.toLowerCase());
  }

}
