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

import static io.meeds.oauth2.server.util.EntityMapper.CLIENT_DISPLAYED_SETTING;
import static io.meeds.oauth2.server.util.EntityMapper.CLIENT_ENABLED_SETTING;
import static io.meeds.oauth2.server.util.EntityMapper.CLIENT_LOGO_URI_SETTING;
import static io.meeds.oauth2.server.util.EntityMapper.CLIENT_POLICY_URI_SETTING;
import static io.meeds.oauth2.server.util.EntityMapper.CLIENT_SERVICE_SETTING;
import static io.meeds.oauth2.server.util.EntityMapper.CLIENT_SYSTEM_SETTING;
import static io.meeds.oauth2.server.util.EntityMapper.CLIENT_URI_SETTING;
import static io.meeds.oauth2.server.util.EntityMapper.CLIENT_UUID_SETTING;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.security.Principal;
import java.util.Base64;
import java.util.List;
import java.util.Set;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpStatus;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.web.server.ResponseStatusException;

import org.exoplatform.commons.ObjectAlreadyExistsException;
import org.exoplatform.commons.exception.ObjectNotFoundException;

import io.meeds.oauth2.server.rest.model.OAuthClientRestEntity;
import io.meeds.oauth2.server.service.OAuthClientService;

@ExtendWith(MockitoExtension.class)
class OAuthClientRestTest {

  private static final String    APP_CALLBACK_URL = "https://app/callback";

  private static final String    APP_POLICY_URL   = "https://app/policy";

  private static final String    APP_LOGO_URL     = "https://app/logo.png";

  private static final String    APP_URL          = "https://app";

  private static final String    DENIED           = "denied";

  private static final String    SERVICE_ID       = "service-id";

  private static final String    CLIENT_ID        = "client-id";

  private static final String    USERNAME         = "root";

  private static final Principal PRINCIPAL        = () -> USERNAME;

  @Mock
  private OAuthClientService     oAuthClientService;

  private OAuthClientRest        rest;

  @BeforeEach
  void setUp() {
    rest = new OAuthClientRest();
    ReflectionTestUtils.setField(rest, "oAuthClientService", oAuthClientService);
  }

  @Test
  void getClientsShouldReturnMappedNonServiceClientsOnly() throws Exception {// NOSONAR
    RegisteredClient appClient = registeredClient(CLIENT_ID, "App", false);
    RegisteredClient serviceClient = registeredClient(SERVICE_ID, "Service", true);
    when(oAuthClientService.getClients(USERNAME, true)).thenReturn(List.of(appClient, serviceClient));

    List<OAuthClientRestEntity> clients = rest.getClients(PRINCIPAL, true);

    assertEquals(1, clients.size());
    assertEquals(CLIENT_ID, clients.get(0).id());
    assertEquals("App", clients.get(0).name());
    verify(oAuthClientService).getClients(USERNAME, true);
  }

  @Test
  void getClientsShouldReturnForbiddenWhenServiceRejectsAccess() throws Exception {// NOSONAR
    when(oAuthClientService.getClients(USERNAME, true)).thenThrow(new IllegalAccessException(DENIED));

    ResponseStatusException exception = assertThrows(ResponseStatusException.class,
                                                     () -> rest.getClients(PRINCIPAL, true));

    assertEquals(HttpStatus.FORBIDDEN, exception.getStatusCode());
  }

  @Test
  void getClientShouldDecodeClientIdAndReturnMappedClient() throws Exception {// NOSONAR
    when(oAuthClientService.getClient(CLIENT_ID, false, USERNAME)).thenReturn(registeredClient(CLIENT_ID, "App", false));

    OAuthClientRestEntity entity = rest.getClient(PRINCIPAL, encoded(CLIENT_ID), false);

    assertEquals(CLIENT_ID, entity.id());
    assertEquals("App", entity.name());
    verify(oAuthClientService).getClient(CLIENT_ID, false, USERNAME);
  }

  @Test
  void getClientShouldReturnNotFoundWhenClientIsHiddenServiceClient() throws Exception {// NOSONAR
    when(oAuthClientService.getClient(SERVICE_ID, true, USERNAME)).thenReturn(registeredClient(SERVICE_ID, "Service", true));

    ResponseStatusException exception = assertThrows(ResponseStatusException.class,
                                                     () -> rest.getClient(PRINCIPAL, encoded(SERVICE_ID), true));

    assertEquals(HttpStatus.NOT_FOUND, exception.getStatusCode());
  }

  @Test
  void getClientShouldReturnForbiddenWhenServiceRejectsAccess() throws Exception {// NOSONAR
    when(oAuthClientService.getClient(CLIENT_ID, true, USERNAME)).thenThrow(new IllegalAccessException(DENIED));

    ResponseStatusException exception = assertThrows(ResponseStatusException.class,
                                                     () -> rest.getClient(PRINCIPAL, encoded(CLIENT_ID), true));

    assertEquals(HttpStatus.FORBIDDEN, exception.getStatusCode());
  }

  @Test
  void getClientByParamShouldDelegateToGetClient() throws Exception {// NOSONAR
    when(oAuthClientService.getClient(CLIENT_ID, false, USERNAME)).thenReturn(registeredClient(CLIENT_ID, "App", false));

    OAuthClientRestEntity entity = rest.getClientByParam(PRINCIPAL, encoded(CLIENT_ID), false);

    assertEquals(CLIENT_ID, entity.id());
    verify(oAuthClientService).getClient(CLIENT_ID, false, USERNAME);
  }

  @Test
  void createClientShouldMapEntityAndReturnCreatedClient() throws Exception {// NOSONAR
    OAuthClientRestEntity input = new OAuthClientRestEntity(CLIENT_ID,
                                                            null,
                                                            "App",
                                                            APP_URL,
                                                            APP_LOGO_URL,
                                                            APP_POLICY_URL,
                                                            true,
                                                            null,
                                                            null,
                                                            Set.of(OidcScopes.OPENID),
                                                            Set.of(APP_CALLBACK_URL));
    when(oAuthClientService.createClient(any(RegisteredClient.class))).thenReturn(registeredClient(CLIENT_ID, "App", false));

    OAuthClientRestEntity created = rest.createClient(input);

    assertEquals(CLIENT_ID, created.id());
    assertEquals("App", created.name());
    verify(oAuthClientService).createClient(any(RegisteredClient.class));
  }

  @Test
  void createClientShouldReturnConflictWhenClientAlreadyExists() throws Exception { // NOSONAR
    OAuthClientRestEntity input = new OAuthClientRestEntity(CLIENT_ID,
                                                            null,
                                                            "App",
                                                            null,
                                                            null,
                                                            null,
                                                            true,
                                                            null,
                                                            null,
                                                            Set.of(OidcScopes.OPENID),
                                                            Set.of(APP_CALLBACK_URL));
    when(oAuthClientService.createClient(any(RegisteredClient.class))).thenThrow(new ObjectAlreadyExistsException(CLIENT_ID));

    ResponseStatusException exception = assertThrows(ResponseStatusException.class, () -> rest.createClient(input));

    assertEquals(HttpStatus.CONFLICT, exception.getStatusCode());
  }

  @Test
  void deleteClientShouldDecodeClientIdAndDelegate() throws Exception {// NOSONAR
    rest.deleteClient(encoded(CLIENT_ID));

    verify(oAuthClientService).deleteClient(CLIENT_ID);
  }

  @Test
  void deleteClientShouldReturnNotFoundWhenMissing() throws Exception {// NOSONAR
    doThrow(new ObjectNotFoundException(CLIENT_ID)).when(oAuthClientService).deleteClient(CLIENT_ID);

    ResponseStatusException exception =
                                      assertThrows(ResponseStatusException.class, () -> rest.deleteClient(encoded(CLIENT_ID)));

    assertEquals(HttpStatus.NOT_FOUND, exception.getStatusCode());
  }

  @Test
  void deleteClientShouldReturnForbiddenWhenServiceRejectsAccess() throws Exception {// NOSONAR
    doThrow(new IllegalAccessException(DENIED)).when(oAuthClientService).deleteClient(CLIENT_ID);

    ResponseStatusException exception =
                                      assertThrows(ResponseStatusException.class, () -> rest.deleteClient(encoded(CLIENT_ID)));

    assertEquals(HttpStatus.FORBIDDEN, exception.getStatusCode());
  }

  @Test
  void updateMutatorsShouldDecodeClientIdAndDelegate() throws Exception {// NOSONAR
    Set<String> redirectUris = Set.of(APP_CALLBACK_URL);
    Set<String> scopes = Set.of(OidcScopes.OPENID, OidcScopes.PROFILE);

    rest.updateClientRedirectName(encoded(CLIENT_ID), "New name A");
    rest.updateClientUrl(encoded(CLIENT_ID), APP_URL);
    rest.updateClientLogoUrl(encoded(CLIENT_ID), APP_LOGO_URL);
    rest.updateClientRedirectUris(encoded(CLIENT_ID), redirectUris);
    rest.updateClientScopes(encoded(CLIENT_ID), scopes);
    rest.updateClientVisibility(encoded(CLIENT_ID), true);
    rest.updateClientActivation(encoded(CLIENT_ID), false);

    verify(oAuthClientService).updateClientName(CLIENT_ID, "New name A");
    verify(oAuthClientService).updateClientUrl(CLIENT_ID, APP_URL);
    verify(oAuthClientService).updateClientLogoUrl(CLIENT_ID, APP_LOGO_URL);
    verify(oAuthClientService).updateClientRedirectUris(CLIENT_ID, redirectUris);
    verify(oAuthClientService).updateClientScopes(CLIENT_ID, scopes);
    verify(oAuthClientService).updateClientVisibility(CLIENT_ID, true);
    verify(oAuthClientService).updateClientActivation(CLIENT_ID, false);
  }

  @Test
  void updateClientNameShouldReturnNotFoundWhenMissing() throws Exception {// NOSONAR
    doThrow(new ObjectNotFoundException(CLIENT_ID)).when(oAuthClientService).updateClientName(CLIENT_ID, "New name B");

    ResponseStatusException exception = assertThrows(ResponseStatusException.class,
                                                     () -> rest.updateClientRedirectName(encoded(CLIENT_ID), "New name B"));

    assertEquals(HttpStatus.NOT_FOUND, exception.getStatusCode());
  }

  @Test
  void updateClientNameShouldReturnForbiddenWhenServiceRejectsAccess() throws Exception {// NOSONAR
    doThrow(new IllegalAccessException(DENIED)).when(oAuthClientService).updateClientName(CLIENT_ID, "New name");

    ResponseStatusException exception = assertThrows(ResponseStatusException.class,
                                                     () -> rest.updateClientRedirectName(encoded(CLIENT_ID), "New name"));

    assertEquals(HttpStatus.FORBIDDEN, exception.getStatusCode());
  }

  private static String encoded(String value) {
    return Base64.getEncoder().encodeToString(value.getBytes());
  }

  private static RegisteredClient registeredClient(String id, String name, boolean service) {
    ClientSettings.Builder settings = ClientSettings.builder()
                                                    .setting(CLIENT_UUID_SETTING, id + "-uuid")
                                                    .setting(CLIENT_URI_SETTING, APP_URL)
                                                    .setting(CLIENT_LOGO_URI_SETTING, APP_LOGO_URL)
                                                    .setting(CLIENT_POLICY_URI_SETTING, APP_POLICY_URL)
                                                    .setting(CLIENT_ENABLED_SETTING, true)
                                                    .setting(CLIENT_DISPLAYED_SETTING, true)
                                                    .setting(CLIENT_SYSTEM_SETTING, false);
    if (service) {
      settings.setting(CLIENT_SERVICE_SETTING, true);
    }

    return RegisteredClient.withId(id)
                           .clientId(id)
                           .clientName(name)
                           .clientAuthenticationMethod(ClientAuthenticationMethod.NONE)
                           .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                           .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                           .redirectUri(APP_CALLBACK_URL)
                           .scope(OidcScopes.OPENID)
                           .scope(OidcScopes.PROFILE)
                           .clientSettings(settings.build())
                           .build();
  }
}
