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

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.stereotype.Component;

import io.meeds.oauth2.server.service.OAuthClientService;

@Component
public class OAuthRefreshTokenPublicAuthenticationProvider implements AuthenticationProvider {

  @Autowired
  private OAuthClientService oAuthClientService;

  @Override
  public Authentication authenticate(Authentication authentication) throws AuthenticationException {
    if (!(authentication instanceof OAuth2ClientAuthenticationToken clientAuthentication)
        || !ClientAuthenticationMethod.NONE.equals(clientAuthentication.getClientAuthenticationMethod())) {
      return null;
    } else {
      String clientId = clientAuthentication.getPrincipal().toString();
      RegisteredClient registeredClient = oAuthClientService.getClient(clientId);
      if (registeredClient == null) {
        throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_CLIENT);
      } else if (!registeredClient.getClientAuthenticationMethods().contains(ClientAuthenticationMethod.NONE)) {
        throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_CLIENT);
      } else if (!registeredClient.getAuthorizationGrantTypes()
                                  .contains(AuthorizationGrantType.REFRESH_TOKEN)) {
        throw new OAuth2AuthenticationException(OAuth2ErrorCodes.UNAUTHORIZED_CLIENT);
      } else {
        return new OAuth2ClientAuthenticationToken(registeredClient,
                                                   ClientAuthenticationMethod.NONE,
                                                   null);
      }
    }
  }

  @Override
  public boolean supports(Class<?> authentication) {
    return OAuth2ClientAuthenticationToken.class.isAssignableFrom(authentication);
  }

}
