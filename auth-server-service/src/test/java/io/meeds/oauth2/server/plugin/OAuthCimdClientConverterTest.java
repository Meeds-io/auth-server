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

import static io.meeds.oauth2.server.util.EntityMapper.CLIENT_IS_CIMD_SETTING;
import static io.meeds.oauth2.server.util.EntityMapper.CLIENT_LOGO_URI_SETTING;
import static io.meeds.oauth2.server.util.EntityMapper.CLIENT_POLICY_URI_SETTING;
import static io.meeds.oauth2.server.util.EntityMapper.CLIENT_URI_SETTING;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.when;

import java.lang.reflect.Field;
import java.util.List;
import java.util.Set;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;

import io.meeds.oauth2.server.model.OAuthCimdClientMetadata;
import io.meeds.oauth2.server.service.OAuthSettingService;

class OAuthCimdClientConverterTest {

  private static final String      APP_URL            = "https://client.example.org";

  private static final String      APP_LOGO_URL       = "https://client.example.org/logo.png";

  private static final String      APP_POLICY_URL     = "https://client.example.org/policy";

  private static final String      REFRESH_TOKEN      = "refresh_token";

  private static final String      AUTHORIZATION_CODE = "authorization_code";

  private static final String      APP_CALLBACK_URL   = "https://client.example.org/callback";

  @Mock
  private OAuthSettingService      oAuthSettingService;

  private OAuthCimdClientConverter converter;

  @BeforeEach
  void setUp() throws Exception {
    MockitoAnnotations.openMocks(this);
    converter = new OAuthCimdClientConverter();
    setField(converter, "oAuthSettingService", oAuthSettingService);
  }

  @Test
  void convertShouldMapCimdMetadataToRegisteredClientAndKeepOnlyAllowedScopes() {
    when(oAuthSettingService.getScopes()).thenReturn(Set.of(OidcScopes.OPENID, OidcScopes.PROFILE, OidcScopes.EMAIL));

    OAuthCimdClientMetadata metadata = new OAuthCimdClientMetadata(
                                                                   "https://client.example.org/metadata",
                                                                   "CIMD Client",
                                                                   APP_URL,
                                                                   APP_LOGO_URL,
                                                                   APP_POLICY_URL,
                                                                   List.of(APP_CALLBACK_URL),
                                                                   List.of(AUTHORIZATION_CODE, REFRESH_TOKEN),
                                                                   List.of("code"),
                                                                   "openid unknown",
                                                                   "private_key_jwt",
                                                                   "https://client.example.org/jwks.json");

    RegisteredClient client = converter.convert(metadata, Set.of(OidcScopes.PROFILE, "ignored"));

    assertEquals(metadata.clientId(), client.getId());
    assertEquals(metadata.clientId(), client.getClientId());
    assertEquals("CIMD Client", client.getClientName());
    assertTrue(client.getRedirectUris().contains(APP_CALLBACK_URL));
    assertTrue(client.getScopes().containsAll(Set.of(OidcScopes.OPENID, OidcScopes.PROFILE)));
    assertTrue(!client.getScopes().contains("unknown"));
    assertTrue(!client.getScopes().contains("ignored"));
    assertTrue(client.getAuthorizationGrantTypes().contains(new AuthorizationGrantType(AUTHORIZATION_CODE)));
    assertTrue(client.getAuthorizationGrantTypes().contains(AuthorizationGrantType.REFRESH_TOKEN));
    assertTrue(client.getClientAuthenticationMethods().contains(ClientAuthenticationMethod.PRIVATE_KEY_JWT));

    assertEquals(Boolean.TRUE, client.getClientSettings().getSetting(CLIENT_IS_CIMD_SETTING));
    assertEquals(APP_URL, client.getClientSettings().getSetting(CLIENT_URI_SETTING));
    assertEquals(APP_LOGO_URL, client.getClientSettings().getSetting(CLIENT_LOGO_URI_SETTING));
    assertEquals(APP_POLICY_URL, client.getClientSettings().getSetting(CLIENT_POLICY_URI_SETTING));
    assertEquals("https://client.example.org/jwks.json", client.getClientSettings().getJwkSetUrl());
    assertTrue(client.getClientSettings().isRequireProofKey());
    assertTrue(client.getClientSettings().isRequireAuthorizationConsent());
  }

  @Test
  void convertShouldSupportPublicClientWithoutOptionalUris() {
    when(oAuthSettingService.getScopes()).thenReturn(Set.of(OidcScopes.OPENID));

    OAuthCimdClientMetadata metadata = new OAuthCimdClientMetadata(
                                                                   "https://client.example.org/metadata",
                                                                   "Public CIMD Client",
                                                                   null,
                                                                   null,
                                                                   null,
                                                                   List.of(APP_CALLBACK_URL),
                                                                   List.of(AUTHORIZATION_CODE),
                                                                   List.of("code"),
                                                                   null,
                                                                   "none",
                                                                   null);

    RegisteredClient client = converter.convert(metadata, Set.of(OidcScopes.OPENID));

    assertEquals(ClientAuthenticationMethod.NONE, client.getClientAuthenticationMethods().iterator().next());
    assertEquals(Set.of(OidcScopes.OPENID), client.getScopes());
    assertNull(client.getClientSettings().getJwkSetUrl());
    assertEquals(Boolean.TRUE, client.getClientSettings().getSetting(CLIENT_IS_CIMD_SETTING));
  }

  private static void setField(Object target, String fieldName, Object value) throws Exception { // NOSONAR
    Field field = target.getClass().getDeclaredField(fieldName);
    field.setAccessible(true); // NOSONAR
    field.set(target, value); // NOSONAR
  }
}
