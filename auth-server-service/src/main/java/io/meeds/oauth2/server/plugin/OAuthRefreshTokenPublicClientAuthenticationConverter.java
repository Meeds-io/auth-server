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

import java.util.Collections;

import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.stereotype.Component;

import io.meeds.oauth2.server.service.OAuthClientService;

@Component
public final class OAuthRefreshTokenPublicClientAuthenticationConverter {

  @Autowired
  private OAuthClientService oAuthClientService;

  public AuthenticationConverter converter() {
    return request -> {
      String grantType = request.getParameter(OAuth2ParameterNames.GRANT_TYPE);
      if (!AuthorizationGrantType.REFRESH_TOKEN.getValue().equals(grantType)) {
        return null;
      }
      String clientId = request.getParameter(OAuth2ParameterNames.CLIENT_ID);
      if (StringUtils.isBlank(clientId)) {
        return null;
      }
      RegisteredClient registeredClient = oAuthClientService.getClient(clientId);
      if (registeredClient == null
          || !registeredClient.getClientAuthenticationMethods().contains(ClientAuthenticationMethod.NONE)) {
        return null;
      } else if (!registeredClient.getAuthorizationGrantTypes()
                                  .contains(AuthorizationGrantType.REFRESH_TOKEN)) {
        throw new OAuth2AuthenticationException(OAuth2ErrorCodes.UNAUTHORIZED_CLIENT);
      } else {
        return new OAuth2ClientAuthenticationToken(clientId,
                                                   ClientAuthenticationMethod.NONE,
                                                   null,
                                                   Collections.emptyMap());
      }
    };
  }

}
