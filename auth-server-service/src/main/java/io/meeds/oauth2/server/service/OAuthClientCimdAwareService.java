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

import static io.meeds.oauth2.server.util.OAuthEventType.CLIENT_REGISTER_REJECT_EVENT;

import java.util.Set;

import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.Strings;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Primary;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.stereotype.Component;

import org.exoplatform.services.listener.ListenerService;

import io.meeds.common.ContainerTransactional;
import io.meeds.oauth2.server.model.OAuthCimdClientMetadata;
import io.meeds.oauth2.server.plugin.OAuthCimdClientConverter;
import io.meeds.oauth2.server.plugin.OAuthCimdClientResolver;
import io.meeds.oauth2.server.storage.OAuthClientStorage;

import lombok.extern.slf4j.Slf4j;

/**
 * A {@link RegisteredClientRepository} decorator that lazily resolves and
 * registers CIMD (Client ID Metadata Document) clients directly inside
 * {@link #findByClientId(String)}.
 * <p>
 * This is deliberately independent of Spring Security's internal filter chain /
 * filter ordering: since {@code findByClientId} is the exact method every
 * OAuth2 endpoint filter calls to resolve the client (authorization endpoint
 * validation, the main authorization endpoint, token endpoint client
 * authentication, introspection, etc.), performing the CIMD resolution here
 * means it works no matter which filter calls it, in what order, or how Spring
 * Security's internal filter wiring changes in future versions. This replaces
 * the previous approach of trying to run CIMD registration in an
 * {@code AuthenticationProvider} or a manually-ordered servlet {@code Filter},
 * both of which depended on winning a race against the framework's own
 * client-lookup timing.
 * <p>
 * Marked {@link Primary} so this bean, not the plain
 * {@link OAuthClientStorage}, is the one wired into
 * {@code OAuth2AuthorizationServerConfigurer}. Direct injections of
 * {@link OAuthClientStorage} by its concrete type elsewhere in the codebase are
 * unaffected.
 */
@Slf4j
@Primary
@Component
public class OAuthClientCimdAwareService implements RegisteredClientRepository {

  private static final Set<String> ALLOWED_AUTH_METHODS = Set.of(ClientAuthenticationMethod.NONE.getValue(),
                                                                 ClientAuthenticationMethod.PRIVATE_KEY_JWT.getValue());

  @Autowired
  private OAuthClientStorage       delegate;

  @Autowired
  private OAuthClientService       oAuthClientService;

  @Autowired
  private OAuthSettingService      oAuthSettingService;

  @Autowired
  private OAuthCimdClientResolver  resolver;

  @Autowired
  private OAuthCimdClientConverter converter;

  @Autowired
  private ListenerService          listenerService;

  @Override
  public void save(RegisteredClient registeredClient) {
    delegate.save(registeredClient);
  }

  @Override
  public RegisteredClient findById(String id) {
    return delegate.findById(id);
  }

  @Override
  public RegisteredClient findByClientId(String clientId) {
    RegisteredClient registeredClient = delegate.findByClientId(clientId);
    if (registeredClient == null && isCimdClientId(clientId)) {
      registeredClient = tryRegisterCimdClient(clientId);
    }
    return registeredClient;
  }

  private RegisteredClient tryRegisterCimdClient(String clientId) {
    try {
      return createClientUsingCimd(clientId);
    } catch (Exception e) {
      // Best-effort: don't throw from here. Returning null lets the
      // downstream OAuth2 machinery produce the correct, spec-compliant
      // OAuth2 error (invalid_request / unauthorized_client / etc.)
      // instead of this repository improvising its own error format.
      log.warn("CIMD auto-registration failed for client_id '{}'", clientId, e);
      return null;
    }
  }

  @ContainerTransactional
  private RegisteredClient createClientUsingCimd(String clientId) {
    OAuthCimdClientMetadata clientMetadata = null;
    try {
      clientMetadata = resolver.resolve(clientId);
      if (!clientMetadata.grantTypes().contains(AuthorizationGrantType.AUTHORIZATION_CODE.getValue())) {
        throw new IllegalArgumentException("Client is missing 'authorization_code' Grant Type");
      } else if (!ALLOWED_AUTH_METHODS.contains(clientMetadata.tokenEndpointAuthMethod())) {
        throw new IllegalArgumentException("Unsupported 'token_endpoint_auth_method': %s".formatted(clientMetadata.tokenEndpointAuthMethod()));
      }
      return oAuthClientService.register(converter.convert(clientMetadata, Set.of()));
    } catch (Exception e) {
      listenerService.broadcast(CLIENT_REGISTER_REJECT_EVENT, clientMetadata, e);
      throw e instanceof RuntimeException re ? re : new IllegalStateException(e.getMessage(), e);
    }
  }

  private boolean isCimdClientId(String clientId) {
    return StringUtils.isNotBlank(clientId)
           && Strings.CS.startsWith(clientId, "https://")
           && oAuthSettingService.isAllowedCimdUrl(clientId)
           // A known client, even a disabled one, is never re-resolved: it would
           // fetch the CIMD document, consume the self-registration rate limit
           // and broadcast a rejection event on every request naming it
           && oAuthClientService.getClient(clientId, true) == null;
  }

}
