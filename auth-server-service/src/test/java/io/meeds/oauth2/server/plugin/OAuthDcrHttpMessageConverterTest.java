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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.mockito.Mockito.when;

import java.nio.charset.StandardCharsets;
import java.util.Set;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.springframework.http.MediaType;
import org.springframework.mock.http.MockHttpInputMessage;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.server.authorization.oidc.OidcClientRegistration;

import io.meeds.oauth2.server.service.OAuthSettingService;

class OAuthDcrHttpMessageConverterTest {

  @Mock
  private OAuthSettingService          oAuthSettingService;

  private OAuthDcrHttpMessageConverter converter;

  @BeforeEach
  void setUp() {
    MockitoAnnotations.openMocks(this);
    converter = new OAuthDcrHttpMessageConverter(oAuthSettingService);
  }

  @Test
  void readShouldUseServerScopesWhenScopeClaimIsMissing() throws Exception { // NOSONAR
    when(oAuthSettingService.getScopes()).thenReturn(Set.of(OidcScopes.OPENID, OidcScopes.PROFILE));

    MockHttpInputMessage inputMessage = json("""
        {
          "client_name": "Client",
          "redirect_uris": ["https://client.example.org/callback"],
          "grant_types": ["authorization_code"],
          "response_types": ["code"],
          "token_endpoint_auth_method": "none"
        }
        """);

    OidcClientRegistration registration = converter.read(OidcClientRegistration.class, inputMessage);

    assertEquals(true, registration.getScopes().containsAll(Set.of(OidcScopes.OPENID, OidcScopes.PROFILE)));
  }

  @Test
  void readShouldUseServerScopesWhenScopeClaimIsBlank() throws Exception {// NOSONAR
    when(oAuthSettingService.getScopes()).thenReturn(Set.of(OidcScopes.OPENID, OidcScopes.EMAIL));

    MockHttpInputMessage inputMessage = json("""
        {
          "client_name": "Client",
          "redirect_uris": ["https://client.example.org/callback"],
          "grant_types": ["authorization_code"],
          "response_types": ["code"],
          "token_endpoint_auth_method": "none",
          "scope": "   "
        }
        """);

    OidcClientRegistration registration = converter.read(OidcClientRegistration.class, inputMessage);

    assertEquals(true, registration.getScopes().containsAll(Set.of(OidcScopes.OPENID, OidcScopes.EMAIL)));
  }

  @Test
  void readShouldSplitExplicitScopeClaim() throws Exception {// NOSONAR
    when(oAuthSettingService.getScopes()).thenReturn(Set.of("ignored"));

    MockHttpInputMessage inputMessage = json("""
        {
          "client_name": "Client",
          "redirect_uris": ["https://client.example.org/callback"],
          "grant_types": ["authorization_code"],
          "response_types": ["code"],
          "token_endpoint_auth_method": "none",
          "scope": "openid profile"
        }
        """);

    OidcClientRegistration registration = converter.read(OidcClientRegistration.class, inputMessage);

    assertEquals(Set.of(OidcScopes.OPENID, OidcScopes.PROFILE), Set.copyOf(registration.getScopes()));
  }

  @Test
  void readShouldTreatClientSecretExpiresAtZeroAsNonExpiring() throws Exception {// NOSONAR
    when(oAuthSettingService.getScopes()).thenReturn(Set.of(OidcScopes.OPENID));

    MockHttpInputMessage inputMessage = json("""
        {
          "client_id": "ClientId",
          "client_name": "Client",
          "redirect_uris": ["https://client.example.org/callback"],
          "grant_types": ["authorization_code"],
          "response_types": ["code"],
          "token_endpoint_auth_method": "client_secret_basic",
          "client_secret": "secret",
          "client_secret_expires_at": 0,
          "scope": "openid"
        }
        """);

    OidcClientRegistration registration = converter.read(OidcClientRegistration.class, inputMessage);

    assertNull(registration.getClientSecretExpiresAt());
  }

  private static MockHttpInputMessage json(String payload) {
    MockHttpInputMessage inputMessage = new MockHttpInputMessage(payload.getBytes(StandardCharsets.UTF_8));
    inputMessage.getHeaders().setContentType(MediaType.APPLICATION_JSON);
    return inputMessage;
  }
}
