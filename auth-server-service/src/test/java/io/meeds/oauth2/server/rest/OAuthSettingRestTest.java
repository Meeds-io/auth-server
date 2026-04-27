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
package io.meeds.oauth2.server.rest;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.util.List;
import java.util.Set;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpStatus;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.web.server.ResponseStatusException;

import io.meeds.oauth2.server.service.OAuthSettingService;

@ExtendWith(MockitoExtension.class)
class OAuthSettingRestTest {

  private static final String APP_URL      = "https://app";

  private static final String REDIRECT_URI = "https://app/callback";

  private static final String ORIGIN_URL   = "https://origin";

  private static final String CIMD_URL     = "https://cimd";

  @Mock
  private OAuthSettingService oAuthSettingService;

  private OAuthSettingRest    rest;

  @BeforeEach
  void setUp() {
    rest = new OAuthSettingRest();
    ReflectionTestUtils.setField(rest, "oAuthSettingService", oAuthSettingService);
  }

  @Test
  void gettersShouldDelegateToService() {
    ClientSettings clientSettings = ClientSettings.builder().setting("k", "v").build();
    TokenSettings tokenSettings = TokenSettings.builder().build();
    when(oAuthSettingService.getScopes()).thenReturn(Set.of(OidcScopes.OPENID, OidcScopes.PROFILE));
    when(oAuthSettingService.getIssuerUrl()).thenReturn("https://issuer");
    when(oAuthSettingService.getAllowedRedirectUris()).thenReturn(List.of(REDIRECT_URI));
    when(oAuthSettingService.getAllowedCimdUris()).thenReturn(List.of(CIMD_URL));
    when(oAuthSettingService.getAllowedOrigins()).thenReturn(List.of(ORIGIN_URL));
    when(oAuthSettingService.isAllowAllRedirectUris()).thenReturn(true);
    when(oAuthSettingService.isAllowAllCimdUris()).thenReturn(true);
    when(oAuthSettingService.isAllowAllOrigins()).thenReturn(false);
    when(oAuthSettingService.getPublicClientSettings()).thenReturn(clientSettings);
    when(oAuthSettingService.getPublicClientTokenSettings()).thenReturn(tokenSettings);

    assertEquals(Set.of(OidcScopes.OPENID, OidcScopes.PROFILE), rest.getScopes());
    assertEquals("https://issuer", rest.getIssuerUrl());
    assertEquals(List.of(REDIRECT_URI), rest.getAllowedRedirectUris());
    assertEquals(List.of(CIMD_URL), rest.getAllowedCimdUris());
    assertEquals(List.of(ORIGIN_URL), rest.getAllowedOrigins());
    assertEquals(true, rest.isAllowAllRedirectUris());
    assertEquals(true, rest.isAllowAllCimdUris());
    assertEquals(false, rest.isAllowAllOrigins());
    assertEquals(clientSettings, rest.getPublicClientSettings());
    assertEquals(tokenSettings, rest.getPublicClientTokenSettings());
  }

  @Test
  void allowAllMutatorsShouldDelegateToService() {
    rest.setAllowAllRedirectUris(true);
    rest.setAllowAllCimdUris(false);
    rest.setAllowAllOrigins(true);

    verify(oAuthSettingService).setAllowAllRedirectUris(true);
    verify(oAuthSettingService).setAllowAllCimdUris(false);
    verify(oAuthSettingService).setAllowAllOrigins(true);
  }

  @Test
  void addAllowedValuesShouldDelegateToService() {
    rest.addAllowedRedirectUri(APP_URL);
    rest.addAllowedCimdUri(CIMD_URL);
    rest.addAllowedOrigin(ORIGIN_URL);

    verify(oAuthSettingService).addAllowedRedirectUri(APP_URL);
    verify(oAuthSettingService).addAllowedCimdUri(CIMD_URL);
    verify(oAuthSettingService).addAllowedOrigin(ORIGIN_URL);
  }

  @Test
  void addAllowedRedirectUriShouldReturnBadRequestWhenServiceRejectsValue() {
    whenRejectingRedirectUri("invalid redirect uri");

    ResponseStatusException exception = assertThrows(ResponseStatusException.class,
                                                     () -> rest.addAllowedRedirectUri("bad"));

    assertEquals(HttpStatus.BAD_REQUEST, exception.getStatusCode());
    assertEquals("invalid redirect uri", exception.getReason());
  }

  @Test
  void addAllowedCimdUriShouldReturnBadRequestWhenServiceRejectsValue() {
    whenRejectingCimdUri("invalid cimd uri");

    ResponseStatusException exception = assertThrows(ResponseStatusException.class,
                                                     () -> rest.addAllowedCimdUri("bad"));

    assertEquals(HttpStatus.BAD_REQUEST, exception.getStatusCode());
    assertEquals("invalid cimd uri", exception.getReason());
  }

  @Test
  void addAllowedOriginShouldReturnBadRequestWhenServiceRejectsValue() {
    whenRejectingOrigin("invalid origin");

    ResponseStatusException exception = assertThrows(ResponseStatusException.class,
                                                     () -> rest.addAllowedOrigin("bad"));

    assertEquals(HttpStatus.BAD_REQUEST, exception.getStatusCode());
    assertEquals("invalid origin", exception.getReason());
  }

  @Test
  void removeAllowedValuesShouldDelegateToService() {
    rest.removeAllowedRedirectUri(APP_URL);
    rest.removeAllowedCimdUri(CIMD_URL);
    rest.removeAllowedOrigin(ORIGIN_URL);

    verify(oAuthSettingService).removeAllowedRedirectUri(APP_URL);
    verify(oAuthSettingService).removeAllowedCimdUri(CIMD_URL);
    verify(oAuthSettingService).removeAllowedOrigin(ORIGIN_URL);
  }

  private void whenRejectingRedirectUri(String message) {
    org.mockito.Mockito.doThrow(new IllegalArgumentException(message))
                       .when(oAuthSettingService)
                       .addAllowedRedirectUri("bad");
  }

  private void whenRejectingCimdUri(String message) {
    org.mockito.Mockito.doThrow(new IllegalArgumentException(message))
                       .when(oAuthSettingService)
                       .addAllowedCimdUri("bad");
  }

  private void whenRejectingOrigin(String message) {
    org.mockito.Mockito.doThrow(new IllegalArgumentException(message))
                       .when(oAuthSettingService)
                       .addAllowedOrigin("bad");
  }
}
