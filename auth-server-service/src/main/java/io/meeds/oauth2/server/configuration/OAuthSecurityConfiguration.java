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
package io.meeds.oauth2.server.configuration;

import static org.springframework.security.config.Customizer.withDefaults;

import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.List;

import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.security.oauth2.server.authorization.autoconfigure.servlet.OAuth2AuthorizationServerProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.client.JdkClientHttpRequestFactory;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.CsrfConfigurer;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.authorization.OAuth2AuthorizationEndpointConfigurer;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.authorization.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.authorization.OidcClientRegistrationEndpointConfigurer;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2Token;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationServerMetadata;
import org.springframework.security.oauth2.server.authorization.oidc.OidcProviderConfiguration;
import org.springframework.security.oauth2.server.authorization.oidc.authentication.OidcClientRegistrationAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.token.DelegatingOAuth2TokenGenerator;
import org.springframework.security.oauth2.server.authorization.token.JwtGenerator;
import org.springframework.security.oauth2.server.authorization.token.OAuth2AccessTokenGenerator;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.WebAttributes;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.authentication.preauth.AbstractPreAuthenticatedProcessingFilter;
import org.springframework.security.web.context.DelegatingSecurityContextRepository;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.security.web.context.RequestAttributeSecurityContextRepository;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.security.web.util.matcher.MediaTypeRequestMatcher;
import org.springframework.web.client.RestClient;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.util.UriComponentsBuilder;

import org.exoplatform.commons.utils.CommonsUtils;
import org.exoplatform.services.listener.ListenerService;
import org.exoplatform.web.security.codec.CodecInitializer;

import io.meeds.oauth2.server.configuration.model.OAuthDefaultSettings;
import io.meeds.oauth2.server.plugin.OAuthAuthorizationRequestConverter;
import io.meeds.oauth2.server.plugin.OAuthDcrHttpAuthenticationConverter;
import io.meeds.oauth2.server.plugin.OAuthRefreshTokenGenerator;
import io.meeds.oauth2.server.plugin.OAuthRefreshTokenPublicAuthenticationProvider;
import io.meeds.oauth2.server.plugin.OAuthRefreshTokenPublicClientAuthenticationConverter;
import io.meeds.oauth2.server.security.OAuthDcrAuthenticationProvider;
import io.meeds.oauth2.server.security.OAuthPortalAuthenticationProvider;
import io.meeds.oauth2.server.service.OAuthAccessTokenCustomizerService;
import io.meeds.oauth2.server.service.OAuthClientService;
import io.meeds.oauth2.server.service.OAuthSettingService;
import io.meeds.oauth2.server.web.OAuthCorsConfigurationSource;
import io.meeds.oauth2.server.web.OAuthPortalPreAuthenticatedFilter;

import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;

@Configuration(proxyBeanMethods = false)
@EnableWebSecurity
@EnableMethodSecurity(prePostEnabled = true, securedEnabled = true, jsr250Enabled = true)
@EnableConfigurationProperties({ OAuth2AuthorizationServerProperties.class, OAuthDefaultSettings.class })
@Slf4j
public class OAuthSecurityConfiguration {

  public static final String  CONSENT_URL          = "/portal/consent";

  public static final String  LOGIN_URL            = "/portal/login";

  public static final String  REGISTER_URL         = "/oauth2/register";

  private static final String PUBLIC_RESOURCES_URL = "/.well-known/**";

  @Bean
  @Order(Ordered.HIGHEST_PRECEDENCE)
  SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http,
                                                             OAuthSettingService oAuthSettingService,
                                                             OAuthPortalAuthenticationProvider portalAuthenticationProvider,
                                                             OAuthPortalPreAuthenticatedFilter portalPreAuthenticatedFilter,
                                                             OAuthDcrHttpAuthenticationConverter oAuthDcrHttpAuthenticationConverter,
                                                             OAuthAuthorizationRequestConverter oAuthAuthorizationRequestConverter,
                                                             OAuthRefreshTokenPublicAuthenticationProvider oAuthRefreshTokenPublicAuthenticationProvider,
                                                             OAuthRefreshTokenPublicClientAuthenticationConverter oAuthRefreshTokenPublicClientAuthenticationConverter,
                                                             SecurityContextRepository securityContextRepository,
                                                             @Qualifier("oauthTokenGenerator")
                                                             OAuth2TokenGenerator<? extends OAuth2Token> tokenGenerator,
                                                             @Qualifier("oauthAuthenticationProvider")
                                                             OAuthDcrAuthenticationProvider oauthAuthenticationProvider,
                                                             @Qualifier("oauthAuthenticationEntryPoint")
                                                             AuthenticationEntryPoint oauthAuthenticationEntryPoint,
                                                             @Qualifier("oauthAccessDeniedHandler")
                                                             AccessDeniedHandler oauthAccessDeniedHandler) {
    OAuth2AuthorizationServerConfigurer authorizationServer = new OAuth2AuthorizationServerConfigurer();
    return http.securityMatcher(authorizationServer.getEndpointsMatcher())
               .securityContext(sc -> sc.securityContextRepository(securityContextRepository))
               .csrf(CsrfConfigurer::disable)
               .cors(withDefaults())
               .addFilterBefore(portalPreAuthenticatedFilter, AbstractPreAuthenticatedProcessingFilter.class)
               .authenticationProvider(portalAuthenticationProvider)
               .with(authorizationServer,
                     a -> a.tokenGenerator(tokenGenerator)
                           .authorizationEndpoint(e -> customizeAuthorizationEndpoint(e, oAuthAuthorizationRequestConverter))
                           .authorizationServerMetadataEndpoint(oauth -> oauth.authorizationServerMetadataCustomizer(c -> customizeMetadata(c,
                                                                                                                                            oAuthSettingService)))
                           .clientAuthentication(oauth -> oauth.authenticationConverters(converters -> converters.add(0,
                                                                                                                      oAuthRefreshTokenPublicClientAuthenticationConverter.converter()))
                                                               .authenticationProviders(providers -> providers.add(0,
                                                                                                                   oAuthRefreshTokenPublicAuthenticationProvider)))
                           .oidc(oidc -> oidc.clientRegistrationEndpoint(e -> customizeRegistrationEndpoint(e,
                                                                                                            oauthAuthenticationProvider,
                                                                                                            oAuthDcrHttpAuthenticationConverter))
                                             .providerConfigurationEndpoint(pc -> pc.providerConfigurationCustomizer(c -> customizeMetadata(c,
                                                                                                                                            oAuthSettingService)))
                                             .logoutEndpoint(withDefaults())))
               .authorizeHttpRequests(a -> a.requestMatchers(HttpMethod.OPTIONS, REGISTER_URL)
                                            .permitAll()
                                            .requestMatchers(HttpMethod.HEAD, REGISTER_URL)
                                            .permitAll()
                                            .requestMatchers(HttpMethod.POST, REGISTER_URL)
                                            .permitAll()
                                            .requestMatchers(HttpMethod.GET, REGISTER_URL)
                                            .permitAll()
                                            .requestMatchers(HttpMethod.OPTIONS, PUBLIC_RESOURCES_URL)
                                            .permitAll()
                                            .requestMatchers(HttpMethod.HEAD, PUBLIC_RESOURCES_URL)
                                            .permitAll()
                                            .requestMatchers(HttpMethod.GET, PUBLIC_RESOURCES_URL)
                                            .permitAll()
                                            .anyRequest()
                                            .authenticated())
               .exceptionHandling(e -> e.defaultAuthenticationEntryPointFor(oauthAuthenticationEntryPoint,
                                                                            new MediaTypeRequestMatcher(MediaType.TEXT_HTML))
                                        .accessDeniedHandler(oauthAccessDeniedHandler))
               .build();
  }

  /**
   * Named Bean here instead of Component on purpose to make CORS Enabled in
   * some Web contexts only
   * 
   * @param corsConfigurationSource {@link OAuthCorsConfigurationSource}
   * @return {@link UrlBasedCorsConfigurationSource} service
   */
  @Bean("corsConfigurationSource")
  UrlBasedCorsConfigurationSource corsConfigurationSource(OAuthCorsConfigurationSource corsConfigurationSource) {
    return corsConfigurationSource;
  }

  @Bean
  AuthorizationServerSettings authorizationServerSettings(OAuthSettingService oAuthSettingService) {
    return AuthorizationServerSettings.builder()
                                      .issuer(oAuthSettingService.getIssuerUrl())
                                      .oidcClientRegistrationEndpoint(REGISTER_URL)
                                      .build();
  }

  @Bean
  SecurityContextRepository securityContextRepository() {
    return new DelegatingSecurityContextRepository(new RequestAttributeSecurityContextRepository(),
                                                   new HttpSessionSecurityContextRepository());
  }

  @Bean
  OAuthPortalPreAuthenticatedFilter portalPreAuthenticatedProcessingFilter(OAuthPortalAuthenticationProvider portalAuthenticationManager,
                                                                           SecurityContextRepository securityContextRepository) {
    OAuthPortalPreAuthenticatedFilter filter = new OAuthPortalPreAuthenticatedFilter(portalAuthenticationManager);
    filter.setAuthenticationManager(new ProviderManager(portalAuthenticationManager));
    filter.setSecurityContextRepository(securityContextRepository);
    filter.setCheckForPrincipalChanges(false);
    filter.setContinueFilterChainOnUnsuccessfulAuthentication(true);
    return filter;
  }

  @Bean("oauthAccessDeniedHandler")
  AccessDeniedHandler oauthAccessDeniedHandler() {
    return (request, response, ex) -> {
      if (!response.isCommitted()) {
        request.setAttribute(WebAttributes.ACCESS_DENIED_403, ex);
        response.sendError(HttpStatus.FORBIDDEN.value(), HttpStatus.FORBIDDEN.getReasonPhrase());
      }
    };
  }

  @Bean("oauthAuthenticationEntryPoint")
  AuthenticationEntryPoint oauthAuthenticationEntryPoint() {
    return (request, response, e) -> {
      if (response.isCommitted()) {
        return;
      }
      response.sendRedirect(UriComponentsBuilder.fromUriString(LOGIN_URL)
                                                .queryParam("initialURI", buildInitialUri(request))
                                                .build()
                                                .toUriString());
    };
  }

  // @formatter:off
  /**
   * Override org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientRegistrationAuthenticationProvider
   * in order to allow **DCR** based on 'none' authentication method: **Public** Clients registration.
   * 
   * This authentication provider will be triggered on {@link OidcClientRegistrationAuthenticationToken} type only (see #supports method)
   * 
   * @param oAuthClientService {@link OAuthClientService} used to register public clients
   * @return {@link AuthenticationProvider}
   */
  @Bean("oauthAuthenticationProvider")
  OAuthDcrAuthenticationProvider oauthAuthenticationProvider(OAuthClientService oAuthClientService,
                                                             CodecInitializer codecInitializer,
                                                             PasswordEncoder passwordEncoder,
                                                             ListenerService listenerService) {
    return new OAuthDcrAuthenticationProvider(oAuthClientService,
                                              codecInitializer,
                                              passwordEncoder,
                                              listenerService);
  }
  // @formatter:on

  @Bean("oauthTokenGenerator")
  OAuth2TokenGenerator<? extends OAuth2Token> tokenGenerator(JwtEncoder jwtEncoder, // NOSONAR
                                                             OAuthAccessTokenCustomizerService oAuthAccessTokenCustomizerService,
                                                             OAuthRefreshTokenGenerator oAuthRefreshTokenGenerator) {
    JwtGenerator jwtGenerator = new JwtGenerator(jwtEncoder);
    jwtGenerator.setJwtCustomizer(oAuthAccessTokenCustomizerService::customize);
    OAuth2AccessTokenGenerator oAuth2AccessTokenGenerator = new OAuth2AccessTokenGenerator();
    oAuth2AccessTokenGenerator.setAccessTokenCustomizer(oAuthAccessTokenCustomizerService);
    return new DelegatingOAuth2TokenGenerator(jwtGenerator,
                                              oAuth2AccessTokenGenerator,
                                              oAuthRefreshTokenGenerator);
  }

  @Bean
  RestClient restClient() {
    HttpClient httpClient = HttpClient.newBuilder()
                                      .connectTimeout(Duration.ofSeconds(3))
                                      .followRedirects(HttpClient.Redirect.NEVER)
                                      .build();
    return RestClient.builder()
                     .requestFactory(new JdkClientHttpRequestFactory(httpClient))
                     .build();
  }

  private String buildInitialUri(HttpServletRequest request) {
    String queryString = request.getQueryString();
    if (StringUtils.isBlank(queryString)) {
      return URLEncoder.encode(request.getRequestURI(), StandardCharsets.UTF_8);
    } else {
      return URLEncoder.encode("%s?%s".formatted(request.getRequestURI(), queryString), StandardCharsets.UTF_8);
    }
  }

  private OidcProviderConfiguration.Builder customizeMetadata(OidcProviderConfiguration.Builder metadataBuilder,
                                                              OAuthSettingService oAuthSettingService) {
    return metadataBuilder.clientRegistrationEndpoint(oAuthSettingService.getIssuerUrl()
                                                                         .concat(REGISTER_URL))
                          .tokenEndpointAuthenticationMethod(ClientAuthenticationMethod.NONE.getValue())
                          .tokenIntrospectionEndpointAuthenticationMethods(m -> {
                            m.clear();
                            m.add(ClientAuthenticationMethod.CLIENT_SECRET_BASIC.getValue());
                          })
                          .scopes(scopes -> customizeMetadataScopes(oAuthSettingService, scopes))
                          // CIMD Custom support
                          .claim("client_id_metadata_document_supported", true);
  }

  private OAuth2AuthorizationServerMetadata.Builder customizeMetadata(OAuth2AuthorizationServerMetadata.Builder metadataBuilder,
                                                                      OAuthSettingService oAuthSettingService) {
    return metadataBuilder.clientRegistrationEndpoint(oAuthSettingService.getIssuerUrl()
                                                                         .concat(REGISTER_URL))
                          .tokenEndpointAuthenticationMethod(ClientAuthenticationMethod.NONE.getValue())
                          .tokenIntrospectionEndpointAuthenticationMethods(m -> {
                            m.clear();
                            m.add(ClientAuthenticationMethod.CLIENT_SECRET_BASIC.getValue());
                          })
                          .scopes(scopes -> customizeMetadataScopes(oAuthSettingService, scopes))
                          // CIMD Custom support
                          .claim("client_id_metadata_document_supported", true);
  }

  private OAuth2AuthorizationEndpointConfigurer customizeAuthorizationEndpoint(OAuth2AuthorizationEndpointConfigurer authorizationEndpoint,
                                                                               OAuthAuthorizationRequestConverter oAuthAuthorizationRequestConverter) {
    return authorizationEndpoint.consentPage(CommonsUtils.getCurrentDomain() + CONSENT_URL)
                                .authorizationRequestConverters(c -> c.add(0, oAuthAuthorizationRequestConverter.converter()));
  }

  private OidcClientRegistrationEndpointConfigurer customizeRegistrationEndpoint(OidcClientRegistrationEndpointConfigurer registrationEndpointConfigurer,
                                                                                 OAuthDcrAuthenticationProvider oauthAuthenticationProvider,
                                                                                 OAuthDcrHttpAuthenticationConverter oAuthDcrHttpAuthenticationConverter) {
    return registrationEndpointConfigurer.authenticationProviders(p -> p.add(0, oauthAuthenticationProvider))
                                         .clientRegistrationRequestConverters(c -> c.add(0,
                                                                                         oAuthDcrHttpAuthenticationConverter.converter()));
  }

  private void customizeMetadataScopes(OAuthSettingService oAuthSettingService, List<String> scopes) {
    oAuthSettingService.getScopes()
                       .stream()
                       .filter(s -> !scopes.contains(s))
                       .forEach(scopes::add);
  }

}
