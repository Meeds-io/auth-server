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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.when;

import java.lang.reflect.Field;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Set;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.core.Ordered;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenClaimsContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenClaimsSet;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenContext;

import org.exoplatform.container.PortalContainer;

import io.meeds.oauth2.server.configuration.plugin.OAuthAccessTokenAudienceProvider;
import io.meeds.oauth2.server.configuration.plugin.OAuthAccessTokenAuthorityProvider;

/**
 * Pins how {@link OAuthAccessTokenCustomizerService} combines its providers:
 * ascending {@code getOrder()} for which answer becomes the claim, and a
 * refusal raised by any audience provider that holds wherever it sorts.
 */
@ExtendWith(MockitoExtension.class)
class OAuthAccessTokenCustomizerServiceTest {

  @Mock
  private PortalContainer                   portalContainer;

  @InjectMocks
  private OAuthAccessTokenCustomizerService customizerService;

  @Test
  @DisplayName("The audience comes from the provider with the lowest order")
  void audienceComesFromTheLowestOrder() {
    initWith(List.of(audience(10, "ten"), audience(0, "zero")), List.of());

    assertEquals(List.of("zero"), customizeAccessToken().getAudience());
  }

  /**
   * Pins the extreme pair against an overflow-free comparator sorting the
   * wrong way ({@code Integer.compare(p2, p1)}, or {@code p1 - p2} which also
   * overflows); {@link #audienceComesFromTheLowestOrder()} is the pin against
   * the descending subtraction, which happens to order this pair correctly.
   */
  @Test
  @DisplayName("HIGHEST_PRECEDENCE sorts before LOWEST_PRECEDENCE")
  void highestPrecedenceSortsBeforeLowestPrecedence() {
    initWith(List.of(audience(Ordered.LOWEST_PRECEDENCE, "last"), audience(Ordered.HIGHEST_PRECEDENCE, "first")),
             List.of());

    assertEquals(List.of("first"), customizeAccessToken().getAudience());
  }

  @Test
  @DisplayName("A provider added after startup takes its place in the order")
  void addedProviderTakesItsPlaceInTheOrder() {
    initWith(List.of(audience(Ordered.LOWEST_PRECEDENCE, "last")), List.of());

    customizerService.addProvider(audience(Ordered.HIGHEST_PRECEDENCE, "first"));

    assertEquals(List.of("first"), customizeAccessToken().getAudience());
  }

  @Test
  @DisplayName("Adding a provider leaves the list a token request already holds untouched")
  void addingAProviderLeavesTheHeldListUntouched() throws ReflectiveOperationException {
    initWith(List.of(audience(Ordered.LOWEST_PRECEDENCE, "last")), List.of(authorities(0, "zero")));
    List<?> heldAudienceProviders = List.copyOf(fieldValue("audienceProviders"));
    List<?> heldAudienceProvidersReference = fieldValue("audienceProviders");
    List<?> heldAuthorityProvidersReference = fieldValue("authorityProviders");

    customizerService.addProvider(audience(Ordered.HIGHEST_PRECEDENCE, "first"));
    customizerService.addProvider(authorities(Ordered.HIGHEST_PRECEDENCE, "first"));

    assertEquals(heldAudienceProviders, heldAudienceProvidersReference);
    assertEquals(1, heldAuthorityProvidersReference.size());
    assertEquals(2, fieldValue("audienceProviders").size());
  }

  @Test
  @DisplayName("A refusal sorted after a provider that already answered still refuses the token")
  void refusalBehindAnAnsweringProviderRefusesTheToken() {
    initWith(List.of(audience(Ordered.HIGHEST_PRECEDENCE, "first"), refusal(Ordered.LOWEST_PRECEDENCE)), List.of());

    OAuth2AuthenticationException exception = assertThrows(OAuth2AuthenticationException.class,
                                                           this::customizeAccessToken);
    assertEquals(OAuth2ErrorCodes.ACCESS_DENIED, exception.getError().getErrorCode());
  }

  @Test
  @DisplayName("A refusal sorted before a provider that would answer refuses the token, in either registration order")
  void refusalBeforeAnAnsweringProviderRefusesTheToken() {
    for (List<OAuthAccessTokenAudienceProvider> providers : List.of(List.of(refusal(Ordered.HIGHEST_PRECEDENCE),
                                                                           audience(Ordered.LOWEST_PRECEDENCE, "resource")),
                                                                   List.of(audience(Ordered.LOWEST_PRECEDENCE, "resource"),
                                                                           refusal(Ordered.HIGHEST_PRECEDENCE)))) {
      initWith(providers, List.of());

      OAuth2AuthenticationException exception = assertThrows(OAuth2AuthenticationException.class,
                                                             this::customizeAccessToken);
      assertEquals(OAuth2ErrorCodes.ACCESS_DENIED, exception.getError().getErrorCode());
    }
  }

  @Test
  @DisplayName("A token no provider names an audience for is an invalid request")
  void noAudienceIsAnInvalidRequest() {
    initWith(List.of(audience(0), audience(10)), List.of());

    OAuth2AuthenticationException exception = assertThrows(OAuth2AuthenticationException.class,
                                                           this::customizeAccessToken);
    assertEquals(OAuth2ErrorCodes.INVALID_REQUEST, exception.getError().getErrorCode());
  }

  @Test
  @DisplayName("The authorities come from the provider with the lowest order")
  void authoritiesComeFromTheLowestOrder() {
    initWith(List.of(audience(0, "aud")), List.of(authorities(10, "ten"), authorities(0, "zero")));

    assertEquals(Set.of("zero"), Set.copyOf(customizeAccessToken().<List<String>> getClaim("authorities")));
  }

  private void initWith(List<OAuthAccessTokenAudienceProvider> audienceProviders,
                        List<OAuthAccessTokenAuthorityProvider> authorityProviders) {
    when(portalContainer.getComponentInstancesOfType(OAuthAccessTokenAudienceProvider.class)).thenReturn(new ArrayList<>(audienceProviders));
    when(portalContainer.getComponentInstancesOfType(OAuthAccessTokenAuthorityProvider.class)).thenReturn(new ArrayList<>(authorityProviders));
    customizerService.init();
  }

  private List<?> fieldValue(String name) throws ReflectiveOperationException {
    Field field = OAuthAccessTokenCustomizerService.class.getDeclaredField(name);
    field.setAccessible(true);
    return (List<?>) field.get(customizerService);
  }

  private OAuth2TokenClaimsSet customizeAccessToken() {
    RegisteredClient client = RegisteredClient.withId("client-id")
                                              .clientId("client")
                                              .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                                              .build();
    OAuth2TokenClaimsContext context = OAuth2TokenClaimsContext.with(OAuth2TokenClaimsSet.builder())
                                                               .registeredClient(client)
                                                               .tokenType(OAuth2TokenType.ACCESS_TOKEN)
                                                               .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                                                               .authorizedScopes(Set.of("read"))
                                                               .build();
    customizerService.customize(context);
    return context.getClaims().build();
  }

  private static OAuthAccessTokenAudienceProvider audience(int order, String... audiences) {
    return new OAuthAccessTokenAudienceProvider() {
      @Override
      public List<String> provideAudiences(OAuth2TokenContext context) {
        return audiences.length == 0 ? null : Arrays.asList(audiences);
      }

      @Override
      public int getOrder() {
        return order;
      }
    };
  }

  private static OAuthAccessTokenAudienceProvider refusal(int order) {
    return new OAuthAccessTokenAudienceProvider() {
      @Override
      public List<String> provideAudiences(OAuth2TokenContext context) {
        throw new OAuth2AuthenticationException(new OAuth2Error(OAuth2ErrorCodes.ACCESS_DENIED));
      }

      @Override
      public int getOrder() {
        return order;
      }
    };
  }

  private static OAuthAccessTokenAuthorityProvider authorities(int order, String... authorities) {
    return new OAuthAccessTokenAuthorityProvider() {
      @Override
      public Set<String> provideAuthorities(OAuth2TokenContext context) {
        return Set.of(authorities);
      }

      @Override
      public int getOrder() {
        return order;
      }
    };
  }

}
