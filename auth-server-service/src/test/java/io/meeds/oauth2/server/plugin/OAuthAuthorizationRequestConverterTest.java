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
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.lang.reflect.Field;
import java.util.Set;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.web.authentication.AuthenticationConverter;

import io.meeds.oauth2.server.service.OAuthClientService;

class OAuthAuthorizationRequestConverterTest {

  private static final String                CLIENT_ID           = "client";

  private static final String                DELEGATE_FIELD_NAME = "delegate";

  private static final String                AUTHORIZE_ENDPOINT  = "/oauth2/authorize";

  @Mock
  private OAuthClientService                 oAuthClientService;

  private OAuthAuthorizationRequestConverter converter;

  @BeforeEach
  void setUp() throws Exception {
    MockitoAnnotations.openMocks(this);
    converter = new OAuthAuthorizationRequestConverter();
    setField(converter, "oAuthClientService", oAuthClientService);
  }

  @Test
  void convertShouldReturnDelegateAuthenticationWhenNotAuthorizationCodeToken() throws Exception {
    AuthenticationConverter delegate = mock(AuthenticationConverter.class);
    org.springframework.security.core.Authentication authentication =
                                                                    mock(org.springframework.security.core.Authentication.class);
    MockHttpServletRequest request = new MockHttpServletRequest("GET", AUTHORIZE_ENDPOINT);
    when(delegate.convert(request)).thenReturn(authentication);
    setField(converter, DELEGATE_FIELD_NAME, delegate);

    org.springframework.security.core.Authentication result = converter.converter().convert(request);

    assertSame(authentication, result);
    verify(oAuthClientService, never()).getClient(org.mockito.ArgumentMatchers.anyString());
  }

  @Test
  void convertShouldReturnTokenAsIsWhenScopesAreAlreadyRequested() throws Exception {
    AuthenticationConverter delegate = mock(AuthenticationConverter.class);
    MockHttpServletRequest request = new MockHttpServletRequest("GET", AUTHORIZE_ENDPOINT);
    OAuth2AuthorizationCodeRequestAuthenticationToken token = authorizationToken(Set.of());
    when(delegate.convert(request)).thenReturn(token);
    setField(converter, DELEGATE_FIELD_NAME, delegate);

    org.springframework.security.core.Authentication result = converter.converter().convert(request);

    assertSame(token, result);
  }

  @Test
  void convertShouldReturnTokenAsIsWhenClientIsUnknown() throws Exception {
    AuthenticationConverter delegate = mock(AuthenticationConverter.class);
    MockHttpServletRequest request = new MockHttpServletRequest("GET", AUTHORIZE_ENDPOINT);
    OAuth2AuthorizationCodeRequestAuthenticationToken token = authorizationToken(Set.of());
    when(delegate.convert(request)).thenReturn(token);
    when(oAuthClientService.getClient(CLIENT_ID)).thenReturn(null);
    setField(converter, DELEGATE_FIELD_NAME, delegate);

    org.springframework.security.core.Authentication result = converter.converter().convert(request);

    assertSame(token, result);
  }

  @Test
  void convertShouldUseRegisteredClientScopesWhenRequestHasNoScopes() throws Exception {
    AuthenticationConverter delegate = mock(AuthenticationConverter.class);
    MockHttpServletRequest request = new MockHttpServletRequest("GET", AUTHORIZE_ENDPOINT);
    OAuth2AuthorizationCodeRequestAuthenticationToken token = authorizationToken(Set.of());
    RegisteredClient registeredClient = RegisteredClient.withId(CLIENT_ID)
                                                        .clientId(CLIENT_ID)
                                                        .clientName("Client")
                                                        .redirectUri("https://client.example.org/callback")
                                                        .scope("openid")
                                                        .scope("profile")
                                                        .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                                                        .build();

    when(delegate.convert(request)).thenReturn(token);
    when(oAuthClientService.getClient(CLIENT_ID)).thenReturn(registeredClient);
    setField(converter, DELEGATE_FIELD_NAME, delegate);

    OAuth2AuthorizationCodeRequestAuthenticationToken result =
                                                             (OAuth2AuthorizationCodeRequestAuthenticationToken) converter.converter()
                                                                                                                          .convert(request);

    assertEquals(Set.of("openid", "profile"), result.getScopes());
    assertEquals(token.getAuthorizationUri(), result.getAuthorizationUri());
    assertEquals(token.getClientId(), result.getClientId());
    assertEquals(token.getRedirectUri(), result.getRedirectUri());
    assertEquals(token.getState(), result.getState());
    assertEquals(token.getAdditionalParameters(), result.getAdditionalParameters());
  }

  private static OAuth2AuthorizationCodeRequestAuthenticationToken authorizationToken(Set<String> scopes) {
    return new OAuth2AuthorizationCodeRequestAuthenticationToken("https://server.example.org/oauth2/authorize",
                                                                 CLIENT_ID,
                                                                 mock(Authentication.class),
                                                                 "https://client.example.org/callback",
                                                                 "state",
                                                                 scopes,
                                                                 java.util.Map.of("prompt", "consent"));
  }

  private static void setField(Object target, String fieldName, Object value) throws Exception { // NOSONAR
    Field field = target.getClass().getDeclaredField(fieldName);
    field.setAccessible(true); // NOSONAR
    field.set(target, value); // NOSONAR
  }
}
