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

import java.util.List;

import org.apache.commons.collections4.MapUtils;
import org.springframework.core.Ordered;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenContext;
import org.springframework.stereotype.Service;

import io.meeds.oauth2.server.configuration.plugin.OAuthJwtAudienceProvider;

@Service
public class OAuthJwtAudienceTokenRequestProvider implements OAuthJwtAudienceProvider {

  @Override
  public List<String> provideAudiences(OAuth2TokenContext context) {
    OAuth2Authorization authorization = context.getAuthorization();
    if (authorization != null) {
      OAuth2AuthorizationRequest authorizationRequest = authorization.getAttribute(OAuth2AuthorizationRequest.class.getName());
      if (authorizationRequest != null
          && MapUtils.isNotEmpty(authorizationRequest.getAdditionalParameters())
          && MapUtils.getString(authorizationRequest.getAdditionalParameters(), "resource") != null) {
        return List.of(MapUtils.getString(authorizationRequest.getAdditionalParameters(), "resource"));
      }
    }
    return null; // NOSONAR
  }

  @Override
  public int getOrder() {
    return Ordered.LOWEST_PRECEDENCE;
  }

}
