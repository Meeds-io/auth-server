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
import org.springframework.test.util.ReflectionTestUtils;

import io.meeds.oauth2.server.model.OAuthConsent;
import io.meeds.oauth2.server.service.OAuthConsentService;

@ExtendWith(MockitoExtension.class)
class OAuthConsentRestTest {

  private static final String    CLIENT_ID = "client-id";

  private static final String    USERNAME  = "root";

  private static final Principal PRINCIPAL = () -> USERNAME;

  @Mock
  private OAuthConsentService    oAuthConsentService;

  private OAuthConsentRest       rest;

  @BeforeEach
  void setUp() {
    rest = new OAuthConsentRest();
    ReflectionTestUtils.setField(rest, "oAuthConsentService", oAuthConsentService);
  }

  @Test
  void getConsentsShouldReturnCurrentUserConsents() {
    OAuthConsent consent = mock(OAuthConsent.class);
    when(oAuthConsentService.getConsentsByUser(USERNAME)).thenReturn(List.of(consent));

    assertEquals(List.of(consent), rest.getConsents(PRINCIPAL));
    verify(oAuthConsentService).getConsentsByUser(USERNAME);
  }

  @Test
  void deleteConsentsByUserShouldDelegateWithCurrentUsername() {
    rest.deleteConsentsByUser(PRINCIPAL);

    verify(oAuthConsentService).deleteConsentsByUser(USERNAME);
  }

  @Test
  void deleteConsentByUserAndClientShouldDecodeClientIdAndDelegate() {
    rest.deleteConsentByUserAndClient(PRINCIPAL, Base64.getEncoder().encodeToString(CLIENT_ID.getBytes()));

    verify(oAuthConsentService).deleteConsentByUserAndClient(USERNAME, CLIENT_ID);
  }

  @Test
  void deleteConsentsByClientShouldDecodeClientIdAndDelegate() {
    rest.deleteConsentsByClient(Base64.getEncoder().encodeToString(CLIENT_ID.getBytes()));

    verify(oAuthConsentService).deleteConsentsByClient(CLIENT_ID);
  }
}
