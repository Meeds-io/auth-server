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
import static org.junit.jupiter.api.Assertions.assertNull;

import java.time.Instant;
import java.util.List;

import org.junit.jupiter.api.Test;

class OAuthJwkSetTest {

  @Test
  void allArgsConstructorShouldSetEntries() {
    Instant activatedAt = Instant.parse("2026-01-01T10:00:00Z");
    OAuthJwkSet.OAuthJwkEntry entry = new OAuthJwkSet.OAuthJwkEntry("{\"kty\":\"RSA\"}", activatedAt);

    OAuthJwkSet jwkSet = new OAuthJwkSet(List.of(entry));

    assertEquals(1, jwkSet.getEntries().size());
    assertEquals("{\"kty\":\"RSA\"}", jwkSet.getEntries().get(0).getKeyPairJson());
    assertEquals(activatedAt, jwkSet.getEntries().get(0).getActivatedAt());
  }

  @Test
  void noArgsConstructorAndSettersShouldWork() {
    OAuthJwkSet jwkSet = new OAuthJwkSet();
    assertNull(jwkSet.getEntries());

    OAuthJwkSet.OAuthJwkEntry entry = new OAuthJwkSet.OAuthJwkEntry();
    entry.setKeyPairJson("{\"kty\":\"EC\"}");
    entry.setActivatedAt(Instant.parse("2026-01-01T10:00:00Z"));

    jwkSet.setEntries(List.of(entry));

    assertEquals("{\"kty\":\"EC\"}", jwkSet.getEntries().get(0).getKeyPairJson());
    assertEquals(Instant.parse("2026-01-01T10:00:00Z"), jwkSet.getEntries().get(0).getActivatedAt());
  }
}
