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
package io.meeds.oauth2.server.security;

import java.util.Set;

import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationException;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.stereotype.Component;

import io.meeds.common.ContainerTransactional;
import io.meeds.oauth2.server.model.OAuthCimdClientMetadata;
import io.meeds.oauth2.server.plugin.OAuthCimdClientConverter;
import io.meeds.oauth2.server.plugin.OAuthCimdClientResolver;
import io.meeds.oauth2.server.service.OAuthClientService;
import io.meeds.oauth2.server.service.OAuthSettingService;

/**
 * A Public Oauth clients Registration Handler which will auto-register allowed
 * CIMD URI(s)
 */
@Component
public class OAuthCimdAuthenticationProvider implements AuthenticationProvider {

  private static final Set<String> ALLOWED_AUTH_METHODS = Set.of(ClientAuthenticationMethod.NONE.getValue(),
                                                                 ClientAuthenticationMethod.PRIVATE_KEY_JWT.getValue());

  @Autowired
  private OAuthClientService       oAuthClientService;

  @Autowired
  private OAuthSettingService      oAuthSettingService;

  @Autowired
  private OAuthCimdClientResolver  resolver;

  @Autowired
  private OAuthCimdClientConverter converter;

  @Override
  public boolean supports(Class<?> authentication) {
    return OAuth2AuthorizationCodeRequestAuthenticationToken.class.isAssignableFrom(authentication);
  }

  @Override
  public Authentication authenticate(Authentication authentication) {
    // @formatter:off
    OAuth2AuthorizationCodeRequestAuthenticationToken authenticationToken = (OAuth2AuthorizationCodeRequestAuthenticationToken) authentication;
    // @formatter:on
    if (isCimdClientId(authenticationToken.getClientId())) {
      createClientUsingCimd(authenticationToken);
    }
    return null;
  }

  @ContainerTransactional
  private void createClientUsingCimd(OAuth2AuthorizationCodeRequestAuthenticationToken authenticationToken) {
    String clientId = authenticationToken.getClientId();
    String redirectUri = authenticationToken.getRedirectUri();
    OAuthCimdClientMetadata clientMetadata = resolver.resolve(clientId);
    if (redirectUri == null
        || !clientMetadata.redirectUris().contains(redirectUri)) {
      throwError(OAuth2ErrorCodes.INVALID_REQUEST,
                 "Invalid redirect_uri '%s' for CIMD. Allowed Client Redirect Uris: %s".formatted(redirectUri,
                                                                                                  StringUtils.join(clientMetadata.redirectUris(),
                                                                                                                   ", ")));
    } else if (!clientMetadata.grantTypes().contains(AuthorizationGrantType.AUTHORIZATION_CODE.getValue())) {
      throwError(OAuth2ErrorCodes.UNAUTHORIZED_CLIENT,
                 "Client is missing 'authorization_code' Grant Type");
    } else if (!ALLOWED_AUTH_METHODS.contains(clientMetadata.tokenEndpointAuthMethod())) {
      throwError(OAuth2ErrorCodes.INVALID_CLIENT,
                 "Unsupported 'token_endpoint_auth_method': %s".formatted(clientMetadata.tokenEndpointAuthMethod()));
    } else {
      registerClient(clientMetadata, authenticationToken.getScopes());
    }
  }

  private void throwError(String code, String description) {
    OAuth2Error error = new OAuth2Error(code, description, null);
    throw new OAuth2AuthorizationCodeRequestAuthenticationException(error, null);
  }

  private boolean isCimdClientId(String clientId) {
    return StringUtils.startsWith(clientId, "https://")
           && oAuthSettingService.isAllowedCimdUrl(clientId)
           && oAuthClientService.getClient(clientId, true) == null;
  }

  private void registerClient(OAuthCimdClientMetadata clientMetadata, Set<String> scopes) {
    RegisteredClient registeredClient = converter.convert(clientMetadata, scopes);
    oAuthClientService.register(registeredClient);
  }

}
