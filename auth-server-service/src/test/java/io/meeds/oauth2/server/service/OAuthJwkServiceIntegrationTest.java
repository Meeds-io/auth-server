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

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;

import io.meeds.oauth2.server.test.OAuthServiceIntegrationTestSupport;

@DisplayName("OAuthJwkService integration")
class OAuthJwkServiceIntegrationTest extends OAuthServiceIntegrationTestSupport {

  @Autowired
  private OAuthJwkService jwkService;

  @Test
  void getJwkSetCreatesAndCachesSigningKeys() {
    JWKSet first = jwkService.getJwkSet();
    JWKSet second = jwkService.getJwkSet();

    assertThat(first.getKeys()).isNotEmpty();
    assertThat(first.getKeys()).allSatisfy(key -> {
      assertThat(key.getKeyID()).startsWith("sig-");
      assertThat(key.getKeyUse().identifier()).isEqualTo("sig");
      assertThat(key.getAlgorithm().getName()).isEqualTo("RS256");
    });
    assertThat(second.getKeys()).extracting(JWK::getKeyID)
                                .containsAll(first.getKeys().stream().map(JWK::getKeyID).toList());
  }

  @Test
  void rotationDurationUsesLongestConfiguredTokenLifetime() {
    assertThat(jwkService.getRotationDuration()).isPositive();
  }
}
