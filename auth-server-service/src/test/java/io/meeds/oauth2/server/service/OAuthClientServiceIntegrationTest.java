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

import static io.meeds.oauth2.server.util.EntityMapper.CLIENT_ENABLED_SETTING;
import static io.meeds.oauth2.server.util.EntityMapper.CLIENT_SYSTEM_SETTING;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.time.Duration;
import java.util.Set;
import java.util.UUID;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;

import org.exoplatform.commons.ObjectAlreadyExistsException;
import org.exoplatform.commons.exception.ObjectNotFoundException;

import io.meeds.oauth2.server.test.OAuthServiceIntegrationTestSupport;
import io.meeds.oauth2.server.util.Utils;

import lombok.SneakyThrows;

@DisplayName("OAuthClientService integration")
class OAuthClientServiceIntegrationTest extends OAuthServiceIntegrationTestSupport {

  @Autowired
  private OAuthClientService  clientService;

  @Autowired
  private OAuthSettingService settingService;

  @BeforeEach
  void seedSettings() {
    settingService.setAllowAllRedirectUris(false);
    String prefix = "https://client.com/callback";
    if (!settingService.getAllowedRedirectUris().contains(prefix)) {
      settingService.addAllowedRedirectUri(prefix);
    }
  }

  @Test
  @SneakyThrows
  void createUpdateHideDisableEnableAndDeleteClient() {
    String clientId = "service-client-" + UUID.randomUUID();
    RegisteredClient client = publicClient(clientId, "https://client.com/callback/service-" + UUID.randomUUID());

    RegisteredClient created = clientService.createClient(client);
    assertThat(created.getClientId()).isEqualTo(clientId);
    assertThat(created.getScopes()).contains(OidcScopes.OPENID, Utils.OFFLINE_ACCESS_SCOPE);

    clientService.updateClientName(clientId, "Updated Client");
    assertThat(clientService.getClient(clientId, true).getClientName()).isEqualTo("Updated Client");

    clientService.updateClientUrl(clientId, "https://client.com");
    clientService.updateClientLogoUrl(clientId, "https://client.com/logo.png");
    clientService.updateClientRedirectUris(clientId, Set.of("https://client.com/callback/updated"));
    clientService.updateClientScopes(clientId, Set.of("profile"));
    assertThat(clientService.getClient(clientId, true).getScopes()).contains(OidcScopes.OPENID, Utils.OFFLINE_ACCESS_SCOPE);

    clientService.updateClientVisibility(clientId, false);
    clientService.updateClientActivation(clientId, false);
    assertThat(clientService.getClients(false)).noneMatch(c -> c.getClientId().equals(clientId));

    clientService.updateClientActivation(clientId, true);
    assertThat(clientService.getClient(clientId, false)).isNotNull();

    clientService.deleteClient(clientId);
    assertThat(clientService.getClient(clientId, true)).isNull();
  }

  @Test
  @SneakyThrows
  void createClientRejectsInvalidInputsAndDuplicateClient() {
    String clientId = "duplicate-client-" + UUID.randomUUID();
    RegisteredClient client = publicClient(clientId, "https://client.com/callback/duplicate-" + UUID.randomUUID());

    assertThatThrownBy(() -> clientService.createClient(null)).isInstanceOf(IllegalArgumentException.class);
    clientService.createClient(client);
    assertThatThrownBy(() -> clientService.createClient(client)).isInstanceOf(ObjectAlreadyExistsException.class);
  }

  @Test
  void deleteAndUpdateRejectMissingClient() {
    String missing = "missing-client-" + UUID.randomUUID();

    assertThatThrownBy(() -> clientService.deleteClient(missing)).isInstanceOf(ObjectNotFoundException.class);
    assertThatThrownBy(() -> clientService.updateClientName(missing, "Name")).isInstanceOf(ObjectNotFoundException.class);
  }

  @Test
  @SneakyThrows
  void registerNormalizesPublicClientAndReusesSameRedirectUriClient() {
    String redirectUri = "https://client.com/callback/dcr-" + UUID.randomUUID();
    RegisteredClient request = publicClient("https://client.com/client-metadata-" + UUID.randomUUID(), redirectUri);

    RegisteredClient first = clientService.register(request);
    RegisteredClient second = clientService.register(RegisteredClient.from(request)
                                                                     .clientName("Ignored Name")
                                                                     .scope("profile")
                                                                     .build());

    assertThat(first.getClientId()).isEqualTo(second.getClientId());
    assertThat(first.getClientSettings().isRequireProofKey()).isTrue();
    assertThat(first.getClientSettings().isRequireAuthorizationConsent()).isTrue();
  }

  @Test
  @SneakyThrows
  void disabledClientIsExcludedFromDefaultLookup() {
    String clientId = "disabled-client-" + UUID.randomUUID();
    RegisteredClient client = publicClient(clientId, "https://client.com/callback/disabled-" + UUID.randomUUID());

    clientService.createClient(client);
    clientService.updateClientActivation(clientId, false);

    assertThat(clientService.getClient(clientId, false)).isNull();
    assertThat(clientService.getClient(clientId, true)).isNotNull();
  }

  private RegisteredClient publicClient(String clientId, String redirectUri) {
    return RegisteredClient.withId(clientId + "-id")
                           .clientId(clientId)
                           .clientName("Client " + clientId)
                           .clientAuthenticationMethod(ClientAuthenticationMethod.NONE)
                           .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                           .redirectUri(redirectUri)
                           .scope(OidcScopes.OPENID)
                           .clientSettings(ClientSettings.builder()
                                                         .requireProofKey(true)
                                                         .requireAuthorizationConsent(true)
                                                         .setting(CLIENT_SYSTEM_SETTING, false)
                                                         .setting(CLIENT_ENABLED_SETTING, true)
                                                         .build())
                           .tokenSettings(TokenSettings.builder()
                                                       .authorizationCodeTimeToLive(Duration.ofMinutes(5))
                                                       .accessTokenTimeToLive(Duration.ofMinutes(10))
                                                       .refreshTokenTimeToLive(Duration.ofHours(1))
                                                       .build())
                           .build();
  }
}
