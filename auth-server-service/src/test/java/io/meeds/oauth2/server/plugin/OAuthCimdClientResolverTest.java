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
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mockStatic;
import static org.springframework.test.web.client.ExpectedCount.once;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.header;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.requestTo;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withServerError;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withSuccess;

import java.lang.reflect.Field;
import java.net.URI;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.MockedStatic;
import org.springframework.http.MediaType;
import org.springframework.test.web.client.MockRestServiceServer;
import org.springframework.web.client.RestClient;

import io.meeds.oauth2.server.model.OAuthCimdClientMetadata;
import io.meeds.oauth2.server.util.Utils;

class OAuthCimdClientResolverTest {

  private static final String     CLIENT_ID  = "https://client.example.org/metadata";

  private static final URI        CLIENT_URI = URI.create(CLIENT_ID);

  private OAuthCimdClientResolver resolver;

  private MockRestServiceServer   server;

  @BeforeEach
  void setUp() throws Exception {
    RestClient.Builder builder = RestClient.builder();
    server = MockRestServiceServer.bindTo(builder).build();

    resolver = new OAuthCimdClientResolver();
    setField(resolver, "restClient", builder.build());
  }

  @Test
  void resolveShouldFetchAndValidateCimdMetadata() {
    try (MockedStatic<Utils> utils = mockStatic(Utils.class)) {
      utils.when(() -> Utils.validateUrl(CLIENT_ID)).thenReturn(CLIENT_URI);

      server.expect(once(), requestTo(CLIENT_URI))
            .andExpect(header("Accept", MediaType.APPLICATION_JSON_VALUE))
            .andRespond(withSuccess("""
                {
                  "client_id": "https://client.example.org/metadata",
                  "client_name": "CIMD Client",
                  "client_uri": "https://client.example.org",
                  "logo_uri": "https://client.example.org/logo.png",
                  "policy_uri": "https://client.example.org/policy",
                  "redirect_uris": ["https://client.example.org/callback"],
                  "grant_types": ["authorization_code"],
                  "response_types": ["code"],
                  "scope": "openid profile",
                  "token_endpoint_auth_method": "private_key_jwt",
                  "jwks_uri": "https://client.example.org/jwks.json"
                }
                """, MediaType.APPLICATION_JSON));

      OAuthCimdClientMetadata metadata = resolver.resolve(CLIENT_ID);

      assertEquals(CLIENT_ID, metadata.clientId());
      assertEquals("CIMD Client", metadata.clientName());
      assertEquals("https://client.example.org", metadata.clientUri());
      assertEquals("https://client.example.org/logo.png", metadata.logoUri());
      assertEquals("https://client.example.org/policy", metadata.policyUri());
      assertEquals("private_key_jwt", metadata.tokenEndpointAuthMethod());
      assertEquals("https://client.example.org/jwks.json", metadata.jwksUri());
      assertEquals("https://client.example.org/callback", metadata.redirectUris().get(0));
      server.verify();
    }
  }

  @Test
  void resolveShouldRejectClientIdMismatch() {
    try (MockedStatic<Utils> utils = mockStatic(Utils.class)) {
      utils.when(() -> Utils.validateUrl(CLIENT_ID)).thenReturn(CLIENT_URI);

      server.expect(once(), requestTo(CLIENT_URI))
            .andRespond(withSuccess("""
                {
                  "client_id": "https://other.example.org/metadata",
                  "redirect_uris": ["https://client.example.org/callback"],
                  "grant_types": ["authorization_code"],
                  "response_types": ["code"],
                  "token_endpoint_auth_method": "none"
                }
                """, MediaType.APPLICATION_JSON));

      IllegalStateException exception = assertThrows(IllegalStateException.class, () -> resolver.resolve(CLIENT_ID));

      assertEquals("metadata.client_id must exactly match the client_id URL", exception.getMessage());
    }
  }

  @Test
  void resolveShouldRejectEmptyRedirectUris() {
    try (MockedStatic<Utils> utils = mockStatic(Utils.class)) {
      utils.when(() -> Utils.validateUrl(CLIENT_ID)).thenReturn(CLIENT_URI);

      server.expect(once(), requestTo(CLIENT_URI))
            .andRespond(withSuccess("""
                {
                  "client_id": "https://client.example.org/metadata",
                  "redirect_uris": [],
                  "grant_types": ["authorization_code"],
                  "response_types": ["code"],
                  "token_endpoint_auth_method": "none"
                }
                """, MediaType.APPLICATION_JSON));

      IllegalStateException exception = assertThrows(IllegalStateException.class, () -> resolver.resolve(CLIENT_ID));

      assertEquals(true, exception.getMessage().startsWith("Invalid CIMD JSON document:"));
    }
  }

  @Test
  void resolveShouldRejectPrivateKeyJwtWithoutJwksUri() {
    try (MockedStatic<Utils> utils = mockStatic(Utils.class)) {
      utils.when(() -> Utils.validateUrl(CLIENT_ID)).thenReturn(CLIENT_URI);

      server.expect(once(), requestTo(CLIENT_URI))
            .andRespond(withSuccess("""
                {
                  "client_id": "https://client.example.org/metadata",
                  "redirect_uris": ["https://client.example.org/callback"],
                  "grant_types": ["authorization_code"],
                  "response_types": ["code"],
                  "token_endpoint_auth_method": "private_key_jwt"
                }
                """, MediaType.APPLICATION_JSON));

      IllegalStateException exception = assertThrows(IllegalStateException.class, () -> resolver.resolve(CLIENT_ID));

      assertEquals("jwks_uri is required for 'private_key_jwt' token_endpoint_auth_method", exception.getMessage());
    }
  }

  @Test
  void resolveShouldRejectNoneAuthenticationWithJwksUri() {
    try (MockedStatic<Utils> utils = mockStatic(Utils.class)) {
      utils.when(() -> Utils.validateUrl(CLIENT_ID)).thenReturn(CLIENT_URI);

      server.expect(once(), requestTo(CLIENT_URI))
            .andRespond(withSuccess("""
                {
                  "client_id": "https://client.example.org/metadata",
                  "redirect_uris": ["https://client.example.org/callback"],
                  "grant_types": ["authorization_code"],
                  "response_types": ["code"],
                  "token_endpoint_auth_method": "none",
                  "jwks_uri": "https://client.example.org/jwks.json"
                }
                """, MediaType.APPLICATION_JSON));

      IllegalStateException exception = assertThrows(IllegalStateException.class, () -> resolver.resolve(CLIENT_ID));

      assertEquals("jwks_uri must be empty for 'none' token_endpoint_auth_method", exception.getMessage());
    }
  }

  @Test
  void resolveShouldWrapHttpErrors() {
    try (MockedStatic<Utils> utils = mockStatic(Utils.class)) {
      utils.when(() -> Utils.validateUrl(CLIENT_ID)).thenReturn(CLIENT_URI);

      server.expect(once(), requestTo(CLIENT_URI)).andRespond(withServerError());

      IllegalStateException exception = assertThrows(IllegalStateException.class, () -> resolver.resolve(CLIENT_ID));

      assertEquals(true, exception.getMessage().contains("CIMD fetch for '" + CLIENT_ID + "' failed"));
    }
  }

  @Test
  void resolveShouldPropagateInvalidClientIdUrl() {
    try (MockedStatic<Utils> utils = mockStatic(Utils.class)) {
      utils.when(() -> Utils.validateUrl("not a url")).thenThrow(new IllegalArgumentException("Only HTTPS URLs are allowed"));

      IllegalArgumentException exception =
                                         assertThrows(IllegalArgumentException.class, () -> resolver.resolve("not a url"));

      assertEquals("Only HTTPS URLs are allowed", exception.getMessage());
    }
  }

  private static void setField(Object target, String fieldName, Object value) throws Exception { // NOSONAR
    Field field = target.getClass().getDeclaredField(fieldName);
    field.setAccessible(true);// NOSONAR
    field.set(target, value);// NOSONAR
  }
}
