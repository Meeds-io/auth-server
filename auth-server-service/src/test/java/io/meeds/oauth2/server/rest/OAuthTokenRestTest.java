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
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.security.Principal;
import java.util.Base64;
import java.util.List;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpStatus;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.web.server.ResponseStatusException;

import org.exoplatform.commons.exception.ObjectNotFoundException;

import io.meeds.oauth2.server.model.OAuthAccessToken;
import io.meeds.oauth2.server.service.OAuthTokenService;

@ExtendWith(MockitoExtension.class)
class OAuthTokenRestTest {

  private static final String    TOKEN_ID  = "token-id";

  private static final String    CLIENT_ID = "client-id";

  private static final String    USERNAME  = "john";

  private static final Principal PRINCIPAL = () -> USERNAME;

  @Mock
  private OAuthTokenService      oAuthTokenService;

  private OAuthTokenRest         rest;

  @BeforeEach
  void setUp() {
    rest = new OAuthTokenRest();
    ReflectionTestUtils.setField(rest, "oAuthTokenService", oAuthTokenService);
  }

  @Test
  void getTokensShouldReturnCurrentUserTokens() {
    OAuthAccessToken token = mock(OAuthAccessToken.class);
    when(oAuthTokenService.getTokensByUser(USERNAME)).thenReturn(List.of(token));

    assertEquals(List.of(token), rest.getTokens(PRINCIPAL));
    verify(oAuthTokenService).getTokensByUser(USERNAME);
  }

  @Test
  void deleteTokenByIdShouldDelegateWithCurrentUsername() throws Exception { // NOSONAR
    rest.deleteTokenById(PRINCIPAL, TOKEN_ID);

    verify(oAuthTokenService).deleteTokenById(TOKEN_ID, USERNAME);
  }

  @Test
  void deleteTokenByIdShouldReturnNotFoundWhenTokenDoesNotExist() throws Exception {// NOSONAR
    doThrow(new ObjectNotFoundException(TOKEN_ID)).when(oAuthTokenService).deleteTokenById(TOKEN_ID, USERNAME);

    ResponseStatusException exception = assertThrows(ResponseStatusException.class,
                                                     () -> rest.deleteTokenById(PRINCIPAL, TOKEN_ID));

    assertEquals(HttpStatus.NOT_FOUND, exception.getStatusCode());
  }

  @Test
  void deleteTokenByIdShouldReturnNotFoundWhenUserCannotAccessToken() throws Exception {// NOSONAR
    doThrow(new IllegalAccessException("denied")).when(oAuthTokenService).deleteTokenById(TOKEN_ID, USERNAME);

    ResponseStatusException exception = assertThrows(ResponseStatusException.class,
                                                     () -> rest.deleteTokenById(PRINCIPAL, TOKEN_ID));

    assertEquals(HttpStatus.NOT_FOUND, exception.getStatusCode());
  }

  @Test
  void deleteTokensByClientShouldDecodeClientIdAndDelegate() {
    rest.deleteTokensByClient(Base64.getEncoder().encodeToString(CLIENT_ID.getBytes()));

    verify(oAuthTokenService).deleteTokensByClient(CLIENT_ID);
  }

  @Test
  void deleteTokensByUserAndClientShouldDecodeClientIdAndDelegate() {
    rest.deleteTokensByUserAndClient(USERNAME, Base64.getEncoder().encodeToString(CLIENT_ID.getBytes()));

    verify(oAuthTokenService).deleteTokensByUserAndClient(USERNAME, CLIENT_ID);
  }
}
