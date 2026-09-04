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
package io.meeds.oauth2.server.model;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.util.List;

import org.junit.jupiter.api.Test;

import com.fasterxml.jackson.databind.ObjectMapper;

import lombok.SneakyThrows;

class OAuthCimdClientMetadataTest {

  @Test
  @SneakyThrows
  void jsonShouldDeserializeUsingSnakeCaseProperties() {
    ObjectMapper mapper = new ObjectMapper();

    OAuthCimdClientMetadata metadata = mapper.readValue("""
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
          "token_endpoint_auth_method": "none",
          "jwks_uri": null
        }
        """, OAuthCimdClientMetadata.class);

    assertEquals("https://client.example.org/metadata", metadata.clientId());
    assertEquals("CIMD Client", metadata.clientName());
    assertEquals("https://client.example.org", metadata.clientUri());
    assertEquals("https://client.example.org/logo.png", metadata.logoUri());
    assertEquals("https://client.example.org/policy", metadata.policyUri());
    assertEquals(List.of("https://client.example.org/callback"), metadata.redirectUris());
    assertEquals(List.of("authorization_code"), metadata.grantTypes());
    assertEquals(List.of("code"), metadata.responseTypes());
    assertEquals("openid profile", metadata.scope());
    assertEquals("none", metadata.tokenEndpointAuthMethod());
  }
}
