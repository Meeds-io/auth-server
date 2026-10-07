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
import static io.meeds.oauth2.server.util.EntityMapper.CLIENT_IS_CIMD_SETTING;
import static io.meeds.oauth2.server.util.EntityMapper.CLIENT_IS_DCR_SETTING;
import static io.meeds.oauth2.server.util.EntityMapper.CLIENT_LOGO_URI_SETTING;
import static io.meeds.oauth2.server.util.EntityMapper.CLIENT_SYSTEM_SETTING;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.CALLS_REAL_METHODS;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.never;

import java.time.Duration;
import java.util.Set;
import java.util.UUID;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.MockedStatic;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.test.util.AopTestUtils;
import org.springframework.test.util.ReflectionTestUtils;

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
    // The self-registration rate limit counts calls of the singleton across
    // every test sharing the Spring context
    OAuthClientService clientServiceTarget = AopTestUtils.getTargetObject(clientService);
    ReflectionTestUtils.setField(clientServiceTarget, "lastRegisterCountInstant", null);
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
  void registerNormalizesPublicClientAndIgnoresChangesOnReRegistration() {
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
  void registerKeepsCimdClientIdWhenADcrClientSharesItsRedirectUri() {
    String redirectUri = "https://client.com/callback/shared-" + UUID.randomUUID();
    RegisteredClient dcrClient = clientService.register(dcrClient("dcr-" + UUID.randomUUID(),
                                                                  redirectUri,
                                                                  ClientAuthenticationMethod.CLIENT_SECRET_BASIC));
    String cimdClientId = "https://client.com/client-metadata-" + UUID.randomUUID();

    RegisteredClient cimdClient = clientService.register(cimdClient(cimdClientId, redirectUri));

    assertThat(cimdClient.getClientId()).isEqualTo(cimdClientId);
    assertThat(cimdClient.getClientAuthenticationMethods()).containsExactly(ClientAuthenticationMethod.NONE);
    assertThat(clientService.getClient(dcrClient.getClientId(), false).getClientAuthenticationMethods())
                                                                                                 .containsExactly(ClientAuthenticationMethod.CLIENT_SECRET_BASIC);
  }

  @Test
  @SneakyThrows
  void registerMergesADcrClientIntoTheCimdClientSharingItsRedirectUri() {
    String redirectUri = "https://client.com/callback/shared-" + UUID.randomUUID();
    String cimdClientId = "https://client.com/client-metadata-" + UUID.randomUUID();
    clientService.register(cimdClient(cimdClientId, redirectUri));

    RegisteredClient dcrClient = clientService.register(dcrClient("dcr-" + UUID.randomUUID(),
                                                                  redirectUri,
                                                                  ClientAuthenticationMethod.NONE));

    assertThat(dcrClient.getClientId()).isEqualTo(cimdClientId);
  }

  @Test
  @SneakyThrows
  void registerMergesADcrClientIntoTheDcrClientSharingItsRedirectUri() {
    String redirectUri = "https://client.com/callback/shared-" + UUID.randomUUID();
    RegisteredClient first = clientService.register(dcrClient("dcr-" + UUID.randomUUID(),
                                                              redirectUri,
                                                              ClientAuthenticationMethod.NONE));

    RegisteredClient second = clientService.register(dcrClient("dcr-" + UUID.randomUUID(),
                                                               redirectUri,
                                                               ClientAuthenticationMethod.NONE));

    assertThat(second.getClientId()).isEqualTo(first.getClientId());
  }

  @Test
  @SneakyThrows
  void registerMergesADcrClientIntoTheAdminCreatedClientSharingItsRedirectUri() {
    String redirectUri = "https://client.com/callback/shared-" + UUID.randomUUID();
    String adminClientId = "admin-" + UUID.randomUUID();
    clientService.createClient(publicClient(adminClientId, redirectUri));

    RegisteredClient dcrClient = clientService.register(dcrClient("dcr-" + UUID.randomUUID(),
                                                                  redirectUri,
                                                                  ClientAuthenticationMethod.NONE));

    assertThat(dcrClient.getClientId()).isEqualTo(adminClientId);
  }

  /**
   * The redirect URI allow-list applies to self-registered clients only, not
   * to an existing client a DCR request is merged into.
   */
  @Test
  @SneakyThrows
  void registerMergesADcrClientIntoTheAdminCreatedClientOfARedirectUriNotAllowed() {
    String redirectUri = "https://not-allowed.com/callback/" + UUID.randomUUID();
    String adminClientId = "admin-" + UUID.randomUUID();
    clientService.createClient(publicClient(adminClientId, redirectUri));

    RegisteredClient dcrClient = clientService.register(dcrClient("dcr-" + UUID.randomUUID(),
                                                                  redirectUri,
                                                                  ClientAuthenticationMethod.NONE));

    assertThat(dcrClient.getClientId()).isEqualTo(adminClientId);
  }

  @Test
  @SneakyThrows
  void registerMergesADcrClientIntoTheAdminCreatedClientWhileSelfRegistrationIsDisabled() {
    String redirectUri = "https://client.com/callback/shared-" + UUID.randomUUID();
    String adminClientId = "admin-" + UUID.randomUUID();
    clientService.createClient(publicClient(adminClientId, redirectUri));
    OAuthClientService clientServiceTarget = AopTestUtils.getTargetObject(clientService);
    Object selfRegisterEnabled = ReflectionTestUtils.getField(clientServiceTarget, "selfRegisterEnabled");
    ReflectionTestUtils.setField(clientServiceTarget, "selfRegisterEnabled", false);
    try {
      RegisteredClient dcrClient = clientService.register(dcrClient("dcr-" + UUID.randomUUID(),
                                                                    redirectUri,
                                                                    ClientAuthenticationMethod.NONE));

      assertThat(dcrClient.getClientId()).isEqualTo(adminClientId);
    } finally {
      ReflectionTestUtils.setField(clientServiceTarget, "selfRegisterEnabled", selfRegisterEnabled);
    }
  }

  /**
   * normalizeClient fetches the logo of the client it normalizes; a client
   * refused for its grant types must be refused before it.
   */
  @Test
  void registerDoesNotFetchTheLogoOfAClientRefusedForItsGrantTypes() {
    RegisteredClient request = withLogo(RegisteredClient.from(dcrClient("dcr-" + UUID.randomUUID(),
                                                                        "https://client.com/callback/refused-" + UUID.randomUUID(),
                                                                        ClientAuthenticationMethod.NONE))
                                                        .authorizationGrantType(AuthorizationGrantType.JWT_BEARER)
                                                        .build());

    assertRefusedWithoutFetchingTheLogo(request);
  }

  /**
   * normalizeClient fetches the logo of the client it normalizes; a client
   * refused by the redirect URI allow-list must be refused before it.
   */
  @Test
  void registerDoesNotFetchTheLogoOfAClientRefusedByTheRedirectUriAllowList() {
    RegisteredClient request = withLogo(dcrClient("dcr-" + UUID.randomUUID(),
                                                  "https://not-allowed.com/callback/" + UUID.randomUUID(),
                                                  ClientAuthenticationMethod.NONE));

    assertRefusedWithoutFetchingTheLogo(request);
  }

  /**
   * A DCR request reaches register with the grant types it asked for
   * (OAuthDcrAuthenticationProvider), the JWT Bearer grant included.
   */
  @Test
  void registerDoesNotStoreARefusedClient() {
    String clientId = "dcr-" + UUID.randomUUID();
    RegisteredClient request = RegisteredClient.from(dcrClient(clientId,
                                                               "https://client.com/callback/refused-" + UUID.randomUUID(),
                                                               ClientAuthenticationMethod.NONE))
                                               .authorizationGrantType(AuthorizationGrantType.JWT_BEARER)
                                               .build();

    assertThatThrownBy(() -> clientService.register(request)).isInstanceOf(IllegalStateException.class)
                                                             .hasMessageContaining("Self Registered Client not enabled");
    assertThat(clientService.getClient(clientId, true)).isNull();
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

  private void assertRefusedWithoutFetchingTheLogo(RegisteredClient request) {
    try (MockedStatic<Utils> utils = mockStatic(Utils.class, CALLS_REAL_METHODS)) {
      assertThatThrownBy(() -> clientService.register(request)).isInstanceOf(IllegalStateException.class);
      utils.verify(() -> Utils.validateUrl(anyString()), never());
    }
    assertThat(clientService.getClient(request.getClientId(), true)).isNull();
  }

  private RegisteredClient withLogo(RegisteredClient client) {
    return RegisteredClient.from(client)
                           .clientSettings(ClientSettings.withSettings(client.getClientSettings().getSettings())
                                                         .setting(CLIENT_LOGO_URI_SETTING, "https://logo.client.com/logo.png")
                                                         .build())
                           .build();
  }

  private RegisteredClient dcrClient(String clientId, String redirectUri, ClientAuthenticationMethod authenticationMethod) {
    RegisteredClient client = publicClient(clientId, redirectUri);
    RegisteredClient.Builder builder = RegisteredClient.from(client)
                                                       .clientAuthenticationMethods(m -> {
                                                         m.clear();
                                                         m.add(authenticationMethod);
                                                       })
                                                       .clientSettings(ClientSettings.withSettings(client.getClientSettings()
                                                                                                         .getSettings())
                                                                                     .setting(CLIENT_IS_DCR_SETTING, true)
                                                                                     .build());
    if (!ClientAuthenticationMethod.NONE.equals(authenticationMethod)) {
      builder.clientSecret("dcr-secret");
    }
    return builder.build();
  }

  private RegisteredClient cimdClient(String clientId, String redirectUri) {
    RegisteredClient client = publicClient(clientId, redirectUri);
    return RegisteredClient.from(client)
                           .clientSettings(ClientSettings.withSettings(client.getClientSettings().getSettings())
                                                         .setting(CLIENT_IS_CIMD_SETTING, true)
                                                         .build())
                           .build();
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
