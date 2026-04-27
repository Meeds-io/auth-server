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
package io.meeds.oauth2.server.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.time.Instant;
import java.util.UUID;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;

import org.exoplatform.commons.exception.ObjectNotFoundException;

import io.meeds.oauth2.server.test.OAuthServiceIntegrationTestSupport;

@DisplayName("OAuthTokenService and OAuthConsentService integration")
class OAuthTokenAndConsentServiceIntegrationTest extends OAuthServiceIntegrationTestSupport {

  @Autowired
  private OAuthTokenService                                                                   tokenService;

  @Autowired
  private OAuthConsentService                                                                 consentService;

  @Autowired
  private org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService authorizationService;

  @Autowired
  private RegisteredClientRepository                                                          registeredClientRepository;

  @Test
  void tokenLifecycleCanSaveFindRemoveAndCleanExpiredTokens() {
    String clientId = "token-client-" + UUID.randomUUID();
    RegisteredClient client = client(clientId);
    registeredClientRepository.save(client);

    OAuth2Authorization authorization = authorization(client, "root", "token-" + UUID.randomUUID());
    authorizationService.save(authorization);

    assertThat(tokenService.findById(authorization.getId())).isNotNull();
    assertThat(tokenService.findByToken(authorization.getAccessToken().getToken().getTokenValue(),
                                        OAuth2TokenType.ACCESS_TOKEN)).isNotNull();

    tokenService.remove(authorization);

    assertThat(tokenService.findById(authorization.getId())).isNull();
    assertThat(tokenService.cleanExpiredTokens()).isGreaterThanOrEqualTo(0);
  }

  @Test
  void deleteTokenByIdRejectsUnknownToken() {
    assertThatThrownBy(() -> tokenService.deleteTokenById("missing-" + UUID.randomUUID(), "root"))
                                                                                                  .isInstanceOf(ObjectNotFoundException.class);
  }

  @Test
  void consentReadDeleteOperationsAreSafeForMissingData() {
    String user = "root";
    String clientId = "missing-client-" + UUID.randomUUID();

    assertThat(consentService.getConsentsByUser(user)).isNotNull();
    assertThat(consentService.getConsentsByClient(clientId)).isNotNull();
    assertThat(consentService.getConsent(user, clientId)).isNull();

    consentService.deleteConsentByUserAndClient(user, clientId);
    consentService.deleteConsentsByUser(user);
    consentService.deleteConsentsByClient(clientId);
  }

  private static OAuth2Authorization authorization(RegisteredClient client, String principalName, String tokenValue) {
    OAuth2AccessToken token = new OAuth2AccessToken(
                                                    OAuth2AccessToken.TokenType.BEARER,
                                                    tokenValue,
                                                    Instant.now(),
                                                    Instant.now().plusSeconds(300),
                                                    java.util.Set.of(OidcScopes.OPENID));

    return OAuth2Authorization.withRegisteredClient(client)
                              .principalName(principalName)
                              .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                              .accessToken(token)
                              .build();
  }

  private static RegisteredClient client(String clientId) {
    return RegisteredClient.withId(clientId + "-id")
                           .clientId(clientId)
                           .clientName(clientId)
                           .clientAuthenticationMethod(ClientAuthenticationMethod.NONE)
                           .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                           .scope(OidcScopes.OPENID)
                           .clientSettings(ClientSettings.builder().build())
                           .build();
  }
}
