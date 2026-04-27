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

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.oauth2.core.oidc.OidcScopes;

import io.meeds.oauth2.server.test.OAuthServiceIntegrationTestSupport;
import io.meeds.oauth2.server.util.Utils;

@DisplayName("OAuthSettingService integration")
class OAuthSettingServiceIntegrationTest extends OAuthServiceIntegrationTestSupport {

  @Autowired
  private OAuthSettingService settingService;

  @Test
  void issuerScopesAndAudiencesAreLoadedFromRealConfiguration() {
    assertThat(settingService.getIssuerUrl()).isEqualTo("https://auth.example.test/auth-server");
    assertThat(settingService.getScopes()).contains(OidcScopes.OPENID, Utils.OFFLINE_ACCESS_SCOPE);
    assertThat(settingService.getAllowedAudiences()).isNotEmpty();
  }

  @Test
  void allowedRedirectUriLifecyclePersistsThroughSettings() {
    String redirectUri = "https://client.com/callback/settings-" + java.util.UUID.randomUUID();

    settingService.addAllowedRedirectUri(redirectUri);

    assertThat(settingService.getAllowedRedirectUris()).contains(redirectUri);
    assertThat(settingService.isAllowedRedirectUri(redirectUri)).isTrue();
    assertThat(settingService.isAllowedRedirectUri("https://client.com.evil.com/callback")).isFalse();

    settingService.removeAllowedRedirectUri(redirectUri);

    assertThat(settingService.getAllowedRedirectUris()).doesNotContain(redirectUri);
  }

  @Test
  void allowedCimdUriLifecyclePersistsThroughSettings() {
    String cimdUri = "https://client.com/.well-known/oauth-client-" + java.util.UUID.randomUUID();

    settingService.addAllowedCimdUri(cimdUri);

    assertThat(settingService.getAllowedCimdUris()).contains(cimdUri);
    assertThat(settingService.isAllowedCimdUrl(cimdUri)).isTrue();

    settingService.removeAllowedCimdUri(cimdUri);

    assertThat(settingService.getAllowedCimdUris()).doesNotContain(cimdUri);
  }

  @Test
  void allowedOriginLifecyclePersistsThroughSettings() {
    String origin = "https://origin-" + java.util.UUID.randomUUID() + ".client.com";

    settingService.addAllowedOrigin(origin);

    assertThat(settingService.getAllowedOrigins()).contains(origin);

    settingService.removeAllowedOrigin(origin);

    assertThat(settingService.getAllowedOrigins()).doesNotContain(origin);
  }

  @Test
  void rejectsUnsafeRedirectAndCimdPrefixes() {
    assertThatThrownBy(() -> settingService.addAllowedRedirectUri("https://client.com@evil.com/callback"))
        .isInstanceOf(IllegalArgumentException.class);
    assertThatThrownBy(() -> settingService.addAllowedRedirectUri("https://client.com/callback#fragment"))
        .isInstanceOf(IllegalArgumentException.class);
    assertThatThrownBy(() -> settingService.addAllowedCimdUri("https://client.com@evil.com/.well-known/oauth-client"))
        .isInstanceOf(IllegalArgumentException.class);
  }

  @Test
  void publicClientSettingsAlwaysRequirePkceAndConsent() {
    assertThat(settingService.getPublicClientSettings().isRequireProofKey()).isTrue();
    assertThat(settingService.getPublicClientSettings().isRequireAuthorizationConsent()).isTrue();
    assertThat(settingService.getPublicClientTokenSettings().getAccessTokenTimeToLive()).isNotNull();
  }
}
