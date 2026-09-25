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

import static io.meeds.oauth2.server.util.EntityMapper.CLIENT_SERVICE_SETTING;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.function.BiFunction;

import org.apache.commons.collections4.CollectionUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenClaimNames;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenClaimsContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.stereotype.Service;

import org.exoplatform.container.PortalContainer;

import io.meeds.oauth2.server.configuration.plugin.OAuthAccessTokenAudienceProvider;
import io.meeds.oauth2.server.configuration.plugin.OAuthAccessTokenAuthorityProvider;

import jakarta.annotation.PostConstruct;

@Service
public class OAuthAccessTokenCustomizerService implements OAuth2TokenCustomizer<OAuth2TokenClaimsContext> {

  @Autowired
  private PortalContainer                         portalContainer;

  /**
   * Replaced as a whole, never mutated in place: a token request iterates the
   * list it read while {@link #addProvider} may run from another webapp's
   * startup, and every audience provider must be consulted.
   */
  private volatile List<OAuthAccessTokenAudienceProvider>  audienceProviders;

  private volatile List<OAuthAccessTokenAuthorityProvider> authorityProviders;

  /**
   * Ascending {@code getOrder()}, the Spring {@link org.springframework.core.Ordered}
   * convention: {@code HIGHEST_PRECEDENCE} is consulted first. Compared with
   * {@link Integer#compare}, never by subtraction, which overflows between
   * {@code HIGHEST_PRECEDENCE} and {@code LOWEST_PRECEDENCE}.
   */
  private static final Comparator<OAuthAccessTokenAudienceProvider>  AUDIENCE_PROVIDER_ORDER  =
                                                                                              Comparator.comparingInt(OAuthAccessTokenAudienceProvider::getOrder);

  private static final Comparator<OAuthAccessTokenAuthorityProvider> AUTHORITY_PROVIDER_ORDER =
                                                                                              Comparator.comparingInt(OAuthAccessTokenAuthorityProvider::getOrder);

  @PostConstruct
  public synchronized void init() {
    this.audienceProviders = sorted(portalContainer.getComponentInstancesOfType(OAuthAccessTokenAudienceProvider.class),
                                    null,
                                    AUDIENCE_PROVIDER_ORDER);
    this.authorityProviders = sorted(portalContainer.getComponentInstancesOfType(OAuthAccessTokenAuthorityProvider.class),
                                     null,
                                     AUTHORITY_PROVIDER_ORDER);
  }

  public synchronized void addProvider(OAuthAccessTokenAudienceProvider audienceProvider) {
    this.audienceProviders = sorted(this.audienceProviders, audienceProvider, AUDIENCE_PROVIDER_ORDER);
  }

  public synchronized void addProvider(OAuthAccessTokenAuthorityProvider authorityProvider) {
    this.authorityProviders = sorted(this.authorityProviders, authorityProvider, AUTHORITY_PROVIDER_ORDER);
  }

  @Override
  public void customize(OAuth2TokenClaimsContext context) {
    if (!OAuth2TokenType.ACCESS_TOKEN.equals(context.getTokenType())) {
      return;
    }
    customize(context, context.getClaims()::claim);
  }

  public void customize(JwtEncodingContext context) {
    if (!OAuth2TokenType.ACCESS_TOKEN.equals(context.getTokenType())) {
      return;
    }
    customize(context, context.getClaims()::claim);
  }

  private void customize(OAuth2TokenContext tokenContext, BiFunction<String, Object, Object> claimFn) {
    RegisteredClient client = tokenContext.getRegisteredClient();
    boolean serviceToken = client.getClientSettings().getSetting(CLIENT_SERVICE_SETTING) != null
                           && Boolean.parseBoolean(client.getClientSettings()
                                                         .getSetting(CLIENT_SERVICE_SETTING)
                                                         .toString());

    claimFn.apply("client_id", client.getClientId());
    claimFn.apply("azp", client.getClientId());
    claimFn.apply("grant_type", tokenContext.getAuthorizationGrantType().getValue());
    claimFn.apply("scope", tokenContext.getAuthorizedScopes());
    claimFn.apply("token_kind", serviceToken ? "service" : "user");
    if (tokenContext.getPrincipal() != null) {
      claimFn.apply(OAuth2TokenClaimNames.SUB, tokenContext.getPrincipal().getName());
    }
    Set<String> roles = computeJwtAuthorities(tokenContext);
    if (roles != null) {
      claimFn.apply("authorities", new HashSet<>(roles));
    }
    List<String> audiences = computeJwtAudiences(tokenContext);
    if (audiences != null) {
      claimFn.apply(OAuth2TokenClaimNames.AUD, new ArrayList<>(audiences));
    }
  }

  /**
   * Resolves the {@code aud} claim: the first non-empty answer in provider
   * order. Every provider is consulted, including after that answer, because a
   * provider refuses the token by throwing {@link OAuth2AuthenticationException}
   * and that refusal must hold wherever the provider sorts — a short-circuit
   * would let whichever provider answers first silence every refusal behind it.
   *
   * @param context the access token being issued
   * @return the audiences of the token, never empty
   * @throws OAuth2AuthenticationException raised by a provider refusing the
   *           token, or {@code invalid_request} when no provider answers
   */
  private List<String> computeJwtAudiences(OAuth2TokenContext context) {
    List<String> audiences = null;
    for (OAuthAccessTokenAudienceProvider audienceProvider : audienceProviders) {
      List<String> providedAudiences = audienceProvider.provideAudiences(context);
      if (audiences == null && CollectionUtils.isNotEmpty(providedAudiences)) {
        audiences = providedAudiences;
      }
    }
    if (audiences == null) {
      throw new OAuth2AuthenticationException(new OAuth2Error(OAuth2ErrorCodes.INVALID_REQUEST,
                                                              "No valid audience provided",
                                                              null));
    }
    return audiences;
  }

  /**
   * @param providers  the current providers, may be null
   * @param provider   a provider to add, may be null
   * @param comparator the order to consult them in
   * @return a new list holding both, sorted, so that a list already handed to
   *         a token request is never modified
   */
  private static <T> List<T> sorted(List<T> providers, T provider, Comparator<T> comparator) {
    List<T> result = providers == null ? new ArrayList<>() : new ArrayList<>(providers);
    if (provider != null) {
      result.add(provider);
    }
    result.sort(comparator);
    return result;
  }

  private Set<String> computeJwtAuthorities(OAuth2TokenContext context) {
    return authorityProviders.stream()
                             .map(p -> p.provideAuthorities(context))
                             .filter(CollectionUtils::isNotEmpty)
                             .findFirst()
                             .orElse(null);
  }

}
