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
package io.meeds.oauth2.server.rest.util;

import static io.meeds.oauth2.server.util.EntityMapper.CLIENT_DISPLAYED_SETTING;
import static io.meeds.oauth2.server.util.EntityMapper.CLIENT_ENABLED_SETTING;
import static io.meeds.oauth2.server.util.EntityMapper.CLIENT_LOGO_URI_SETTING;
import static io.meeds.oauth2.server.util.EntityMapper.CLIENT_POLICY_URI_SETTING;
import static io.meeds.oauth2.server.util.EntityMapper.CLIENT_SERVICE_SETTING;
import static io.meeds.oauth2.server.util.EntityMapper.CLIENT_SYSTEM_SETTING;
import static io.meeds.oauth2.server.util.EntityMapper.CLIENT_URI_SETTING;
import static io.meeds.oauth2.server.util.EntityMapper.CLIENT_UUID_SETTING;

import org.apache.commons.lang3.StringUtils;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings.Builder;

import io.meeds.oauth2.server.rest.model.OAuthClientRestEntity;

public class EntityBuilder {

  private EntityBuilder() {
    // Private Class
  }

  public static OAuthClientRestEntity toClientRestEntity(RegisteredClient client) {
    if (client == null || isServiceClient(client)) {
      return null;
    } else {
      return new OAuthClientRestEntity(client.getClientId(),
                                       client.getClientSettings().getSetting(CLIENT_UUID_SETTING),
                                       client.getClientName(),
                                       client.getClientSettings().getSetting(CLIENT_URI_SETTING),
                                       client.getClientSettings().getSetting(CLIENT_LOGO_URI_SETTING),
                                       client.getClientSettings().getSetting(CLIENT_POLICY_URI_SETTING),
                                       client.getClientSettings().getSetting(CLIENT_ENABLED_SETTING),
                                       client.getClientSettings().getSetting(CLIENT_DISPLAYED_SETTING),
                                       client.getClientSettings().getSetting(CLIENT_SYSTEM_SETTING),
                                       client.getScopes(),
                                       client.getRedirectUris());
    }
  }

  public static RegisteredClient fromClientRestEntity(OAuthClientRestEntity entity) {
    if (entity == null) {
      return null;
    } else {
      Builder clientSettingsBuilder = ClientSettings.builder();
      if (StringUtils.isNotBlank(entity.url())) {
        clientSettingsBuilder.setting(CLIENT_URI_SETTING, entity.url());
      }
      if (StringUtils.isNotBlank(entity.logoUrl())) {
        clientSettingsBuilder.setting(CLIENT_LOGO_URI_SETTING, entity.logoUrl());
      }
      if (StringUtils.isNotBlank(entity.policyUrl())) {
        clientSettingsBuilder.setting(CLIENT_POLICY_URI_SETTING, entity.policyUrl());
      }
      clientSettingsBuilder.setting(CLIENT_ENABLED_SETTING, entity.enabled() == null || entity.enabled().booleanValue());
      return RegisteredClient.withId(entity.id())
                             .clientId(entity.id())
                             .clientName(entity.name())
                             .scopes(s -> s.addAll(entity.scopes()))
                             .redirectUris(r -> r.addAll(entity.redirectUris()))
                             .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                             .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                             .clientSettings(clientSettingsBuilder.build())
                             .build();
    }
  }

  public static boolean isServiceClient(RegisteredClient client) {
    return client.getClientSettings().getSetting(CLIENT_SERVICE_SETTING) != null
           && Boolean.parseBoolean(client.getClientSettings()
                                         .getSetting(CLIENT_SERVICE_SETTING)
                                         .toString());
  }

}
