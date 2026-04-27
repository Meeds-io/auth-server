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
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isA;
import static org.mockito.Mockito.when;

import java.lang.reflect.Field;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.server.authorization.oidc.OidcClientRegistration;
import org.springframework.security.oauth2.server.authorization.oidc.authentication.OidcClientRegistrationAuthenticationToken;

class OAuthDcrHttpAuthenticationConverterTest {

  private static final String                 INVALID_REQUEST   = "invalid_request";

  private static final String                 REGISTER_ENDPOINT = "/connect/register";

  private static final String                 CLIENT_ID         = "client-1";

  @Mock
  private OAuthDcrHttpMessageConverter        oAuthDcrHttpMessageConverter;

  private OAuthDcrHttpAuthenticationConverter converter;

  private AutoCloseable                       closeable;

  @BeforeEach
  void setUp() throws Exception {
    closeable = MockitoAnnotations.openMocks(this);
    converter = new OAuthDcrHttpAuthenticationConverter();
    setField(converter, "oAuthDcrHttpMessageConverter", oAuthDcrHttpMessageConverter);
    SecurityContextHolder.getContext().setAuthentication(new TestingAuthenticationToken("root", "N/A"));
  }

  @AfterEach
  void tearDown() throws Exception {
    SecurityContextHolder.clearContext();
    closeable.close();
  }

  @Test
  void convertShouldCreateRegistrationAuthenticationTokenForPostRequest() throws Exception {// NOSONAR
    MockHttpServletRequest request = new MockHttpServletRequest("POST", REGISTER_ENDPOINT);
    OidcClientRegistration registration = OidcClientRegistration.builder()
                                                                .clientId("client")
                                                                .clientName("Client")
                                                                .redirectUri("https://client.example.org/callback")
                                                                .build();
    when(oAuthDcrHttpMessageConverter.read(eq(OidcClientRegistration.class),
                                           isA(org.springframework.http.HttpInputMessage.class)))
                                                                                                 .thenReturn(registration);

    OidcClientRegistrationAuthenticationToken token =
                                                    (OidcClientRegistrationAuthenticationToken) converter.convert(request);

    assertSame(SecurityContextHolder.getContext().getAuthentication(), token.getPrincipal());
    assertSame(registration, token.getClientRegistration());
  }

  @Test
  void convertShouldWrapMessageConverterFailureAsOAuth2AuthenticationException() throws Exception {// NOSONAR
    MockHttpServletRequest request = new MockHttpServletRequest("POST", REGISTER_ENDPOINT);
    when(oAuthDcrHttpMessageConverter.read(eq(OidcClientRegistration.class),
                                           isA(org.springframework.http.HttpInputMessage.class)))
                                                                                                 .thenThrow(new IllegalArgumentException("bad registration"));

    OAuth2AuthenticationException exception =
                                            assertThrows(OAuth2AuthenticationException.class, () -> converter.convert(request));

    assertEquals(INVALID_REQUEST, exception.getError().getErrorCode());
    assertEquals(true, exception.getError().getDescription().contains("OpenID Client Registration Error"));
  }

  @Test
  void convertShouldCreateLookupAuthenticationTokenForGetRequest() {
    MockHttpServletRequest request = new MockHttpServletRequest("GET", REGISTER_ENDPOINT);
    request.setQueryString("client_id=client-1");
    request.addParameter(OAuth2ParameterNames.CLIENT_ID, CLIENT_ID);

    OidcClientRegistrationAuthenticationToken token =
                                                    (OidcClientRegistrationAuthenticationToken) converter.convert(request);

    assertSame(SecurityContextHolder.getContext().getAuthentication(), token.getPrincipal());
    assertEquals(CLIENT_ID, token.getClientId());
  }

  @Test
  void convertShouldRejectMissingClientIdOnGetRequest() {
    MockHttpServletRequest request = new MockHttpServletRequest("GET", REGISTER_ENDPOINT);

    OAuth2AuthenticationException exception =
                                            assertThrows(OAuth2AuthenticationException.class, () -> converter.convert(request));

    assertEquals(INVALID_REQUEST, exception.getError().getErrorCode());
  }

  @Test
  void convertShouldRejectDuplicateClientIdOnGetRequest() {
    MockHttpServletRequest request = new MockHttpServletRequest("GET", REGISTER_ENDPOINT);
    request.setQueryString("client_id=client-1&client_id=client-2");
    request.addParameter(OAuth2ParameterNames.CLIENT_ID, CLIENT_ID, "client-2");

    OAuth2AuthenticationException exception =
                                            assertThrows(OAuth2AuthenticationException.class, () -> converter.convert(request));

    assertEquals(INVALID_REQUEST, exception.getError().getErrorCode());
  }

  @Test
  void convertShouldIgnoreParametersThatAreNotInQueryString() {
    MockHttpServletRequest request = new MockHttpServletRequest("GET", REGISTER_ENDPOINT);
    request.setQueryString("other=value");
    request.addParameter(OAuth2ParameterNames.CLIENT_ID, CLIENT_ID);

    OAuth2AuthenticationException exception =
                                            assertThrows(OAuth2AuthenticationException.class, () -> converter.convert(request));

    assertEquals(INVALID_REQUEST, exception.getError().getErrorCode());
  }

  private static void setField(Object target, String fieldName, Object value) throws Exception {// NOSONAR
    Field field = target.getClass().getDeclaredField(fieldName);
    field.setAccessible(true);// NOSONAR
    field.set(target, value);// NOSONAR
  }
}
