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
package io.meeds.oauth2.server.rest.util;

import static io.meeds.oauth2.server.util.EntityMapper.CLIENT_DISPLAYED_SETTING;
import static io.meeds.oauth2.server.util.EntityMapper.CLIENT_ENABLED_SETTING;
import static io.meeds.oauth2.server.util.EntityMapper.CLIENT_LOGO_URI_SETTING;
import static io.meeds.oauth2.server.util.EntityMapper.CLIENT_POLICY_URI_SETTING;
import static io.meeds.oauth2.server.util.EntityMapper.CLIENT_SERVICE_SETTING;
import static io.meeds.oauth2.server.util.EntityMapper.CLIENT_SYSTEM_SETTING;
import static io.meeds.oauth2.server.util.EntityMapper.CLIENT_URI_SETTING;
import static io.meeds.oauth2.server.util.EntityMapper.CLIENT_UUID_SETTING;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Base64;
import java.util.Set;

import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;

import io.meeds.oauth2.server.rest.model.OAuthClientRestEntity;

class EntityBuilderTest {

  private static final String APP_CALLBACK_URL = "https://app/callback";

  private static final String APP_POLICY_URL   = "https://app/policy";

  private static final String APP_LOGO_URL     = "https://app/logo.png";

  private static final String APP_URL          = "https://app";

  private static final String APP_NAME         = "App";

  private static final String CLIENT_ID_UUID   = "client-id-uuid";

  private static final String CLIENT_ID        = "client-id";

  @Test
  void toClientRestEntityShouldReturnNullForNullClient() {
    assertNull(EntityBuilder.toClientRestEntity(null));
  }

  @Test
  void toClientRestEntityShouldReturnNullForServiceClient() {
    assertNull(EntityBuilder.toClientRestEntity(registeredClient(true)));
  }

  @Test
  void toClientRestEntityShouldMapRegisteredClientSettings() {
    OAuthClientRestEntity entity = EntityBuilder.toClientRestEntity(registeredClient(false));

    assertEquals(CLIENT_ID, entity.id());
    assertEquals(CLIENT_ID_UUID, entity.uuid());
    assertEquals(APP_NAME, entity.name());
    assertEquals(APP_URL, entity.url());
    assertEquals(APP_LOGO_URL, entity.logoUrl());
    assertEquals(APP_POLICY_URL, entity.policyUrl());
    assertEquals(true, entity.enabled());
    assertEquals(true, entity.displayed());
    assertEquals(false, entity.system());
    assertTrue(entity.scopes().containsAll(Set.of(OidcScopes.OPENID, OidcScopes.PROFILE)));
    assertEquals(Set.of(APP_CALLBACK_URL), entity.redirectUris());
  }

  @Test
  void fromClientRestEntityShouldReturnNullForNullEntity() {
    assertNull(EntityBuilder.fromClientRestEntity(null));
  }

  @Test
  void fromClientRestEntityShouldBuildRegisteredClient() {
    OAuthClientRestEntity entity = new OAuthClientRestEntity(CLIENT_ID,
                                                             null,
                                                             APP_NAME,
                                                             APP_URL,
                                                             APP_LOGO_URL,
                                                             APP_POLICY_URL,
                                                             false,
                                                             null,
                                                             null,
                                                             Set.of(OidcScopes.OPENID, OidcScopes.PROFILE),
                                                             Set.of(APP_CALLBACK_URL));

    RegisteredClient client = EntityBuilder.fromClientRestEntity(entity);

    assertEquals(CLIENT_ID, client.getId());
    assertEquals(CLIENT_ID, client.getClientId());
    assertEquals(APP_NAME, client.getClientName());
    assertEquals(Set.of(OidcScopes.OPENID, OidcScopes.PROFILE), client.getScopes());
    assertEquals(Set.of(APP_CALLBACK_URL), client.getRedirectUris());
    assertTrue(client.getAuthorizationGrantTypes().contains(AuthorizationGrantType.AUTHORIZATION_CODE));
    assertTrue(client.getAuthorizationGrantTypes().contains(AuthorizationGrantType.REFRESH_TOKEN));
    assertEquals(APP_URL, client.getClientSettings().getSetting(CLIENT_URI_SETTING));
    assertEquals(APP_LOGO_URL, client.getClientSettings().getSetting(CLIENT_LOGO_URI_SETTING));
    assertEquals(APP_POLICY_URL, client.getClientSettings().getSetting(CLIENT_POLICY_URI_SETTING));
    assertEquals(false, client.getClientSettings().getSetting(CLIENT_ENABLED_SETTING));
  }

  @Test
  void fromClientRestEntityShouldDefaultEnabledToTrue() {
    OAuthClientRestEntity entity = new OAuthClientRestEntity(CLIENT_ID,
                                                             null,
                                                             APP_NAME,
                                                             null,
                                                             null,
                                                             null,
                                                             null,
                                                             null,
                                                             null,
                                                             Set.of(OidcScopes.OPENID),
                                                             Set.of(APP_CALLBACK_URL));

    RegisteredClient client = EntityBuilder.fromClientRestEntity(entity);

    assertEquals(true, client.getClientSettings().getSetting(CLIENT_ENABLED_SETTING));
  }

  @Test
  void decodeBase64ShouldDecodeValidValue() {
    String encoded = Base64.getEncoder().encodeToString(CLIENT_ID.getBytes());

    assertEquals(CLIENT_ID, EntityBuilder.decodeBase64(encoded));
  }

  @Test
  void decodeBase64ShouldReturnOriginalValueWhenInvalid() {
    assertEquals("not-base64", EntityBuilder.decodeBase64("not-base64"));
  }

  @Test
  void isServiceClientShouldReturnFalseWhenSettingIsMissing() {
    assertFalse(EntityBuilder.isServiceClient(registeredClient(false)));
  }

  @Test
  void isServiceClientShouldReturnTrueWhenServiceSettingIsTrue() {
    assertTrue(EntityBuilder.isServiceClient(registeredClient(true)));
  }

  private static RegisteredClient registeredClient(boolean service) {
    ClientSettings.Builder settings = ClientSettings.builder()
                                                    .setting(CLIENT_UUID_SETTING, CLIENT_ID_UUID)
                                                    .setting(CLIENT_URI_SETTING, APP_URL)
                                                    .setting(CLIENT_LOGO_URI_SETTING, APP_LOGO_URL)
                                                    .setting(CLIENT_POLICY_URI_SETTING, APP_POLICY_URL)
                                                    .setting(CLIENT_ENABLED_SETTING, true)
                                                    .setting(CLIENT_DISPLAYED_SETTING, true)
                                                    .setting(CLIENT_SYSTEM_SETTING, false);
    if (service) {
      settings.setting(CLIENT_SERVICE_SETTING, true);
    }

    return RegisteredClient.withId(CLIENT_ID)
                           .clientId(CLIENT_ID)
                           .clientName(APP_NAME)
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
