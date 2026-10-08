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
package io.meeds.oauth2.server.configuration;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Set;

import org.junit.jupiter.api.Test;

import io.meeds.commons.http.SafeFetchPolicy;
import io.meeds.commons.http.SafeHttpFetcher;
import io.meeds.oauth2.server.util.Utils;

/**
 * Pins the policy of the fetcher bean every read of a client-supplied URL goes
 * through: the tests of those reads build their own fetchers, so only this one
 * sees what production runs.
 */
class OAuthUrlFetcherBeanTest {

  /**
   * The bean reads https on port 443 only, follows no redirect, never reaches
   * an internal address and exempts nothing; its limit is the largest of the
   * reads it serves, the metadata document's when the logo's is smaller.
   */
  @Test
  void theFetcherBeanRunsUnderTheProductionPolicy() {
    OAuthSecurityConfiguration configuration = new OAuthSecurityConfiguration();
    try (SafeHttpFetcher small = configuration.oauthUrlFetcher(1024);
         SafeHttpFetcher large = configuration.oauthUrlFetcher(20L * 1024 * 1024)) {
      SafeFetchPolicy policy = small.getPolicy();
      assertEquals(Set.of("https"), policy.getAllowedSchemes());
      assertEquals(Set.of(443), policy.getAllowedPorts());
      assertFalse(policy.isAnyPortAllowed());
      assertEquals(0, policy.getMaxRedirects());
      assertFalse(policy.isInternalAddressesAllowed());
      assertTrue(policy.getExemptHosts().isEmpty());
      assertTrue(policy.getExemptAddresses().isEmpty());
      assertEquals(Utils.CIMD_MAX_BYTES, policy.getMaxBytes(), "a small logo limit never caps the metadata document");
      assertEquals(20L * 1024 * 1024, large.getPolicy().getMaxBytes(), "the logo limit reaches the policy");
      assertEquals(Utils.URL_TOTAL_TIMEOUT, policy.getTotalTimeout());
    }
  }

}
