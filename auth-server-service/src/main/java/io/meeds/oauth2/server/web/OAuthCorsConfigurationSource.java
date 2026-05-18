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
package io.meeds.oauth2.server.web;

import static io.meeds.oauth2.server.util.OAuthEventType.ALLOWED_ORIGINS_ALL_MODIFIED_EVENT;
import static io.meeds.oauth2.server.util.OAuthEventType.ALLOWED_ORIGIN_ADDED_EVENT;
import static io.meeds.oauth2.server.util.OAuthEventType.ALLOWED_ORIGIN_REMOVED_EVENT;
import static io.meeds.oauth2.server.util.OAuthEventType.ALLOWED_REDIRECT_URIS_ALL_MODIFIED_EVENT;
import static io.meeds.oauth2.server.util.OAuthEventType.ALLOWED_REDIRECT_URI_ADDED_EVENT;
import static io.meeds.oauth2.server.util.OAuthEventType.ALLOWED_REDIRECT_URI_REMOVED_EVENT;
import static io.meeds.oauth2.server.util.OAuthEventType.CLIENT_CREATED_EVENT;
import static io.meeds.oauth2.server.util.OAuthEventType.CLIENT_DELETED_EVENT;
import static io.meeds.oauth2.server.util.OAuthEventType.CLIENT_ENABLED_EVENT;
import static io.meeds.oauth2.server.util.OAuthEventType.CLIENT_UPDATED_EVENT;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import org.apache.commons.collections4.CollectionUtils;
import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.server.PathContainer;
import org.springframework.stereotype.Service;
import org.springframework.util.AntPathMatcher;
import org.springframework.util.PathMatcher;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.util.ServletRequestPathUtils;
import org.springframework.web.util.UrlPathHelper;
import org.springframework.web.util.pattern.PathPattern;
import org.springframework.web.util.pattern.PathPatternParser;

import org.exoplatform.services.listener.ListenerService;

import io.meeds.oauth2.server.service.OAuthClientService;
import io.meeds.oauth2.server.service.OAuthSettingService;

import jakarta.annotation.PostConstruct;
import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;

@Service
@Slf4j
public class OAuthCorsConfigurationSource extends UrlBasedCorsConfigurationSource {

  private static final List<String>      EVENT_TYPES          = Arrays.asList(ALLOWED_REDIRECT_URIS_ALL_MODIFIED_EVENT,
                                                                              ALLOWED_REDIRECT_URI_ADDED_EVENT,
                                                                              ALLOWED_REDIRECT_URI_REMOVED_EVENT,
                                                                              ALLOWED_ORIGINS_ALL_MODIFIED_EVENT,
                                                                              ALLOWED_ORIGIN_ADDED_EVENT,
                                                                              ALLOWED_ORIGIN_REMOVED_EVENT,
                                                                              CLIENT_CREATED_EVENT,
                                                                              CLIENT_UPDATED_EVENT,
                                                                              CLIENT_DELETED_EVENT,
                                                                              CLIENT_ENABLED_EVENT);

  private static final PathPatternParser PATTERN_PARSER       = PathPatternParser.defaultInstance;

  @Autowired
  private OAuthClientService             oAuthClientService;

  @Autowired
  private OAuthSettingService            oAuthSettingService;

  @Autowired
  private ListenerService                listenerService;

  @Value("#{'${meeds.oauth.cors.allowed-methods:HEAD,GET,OPTIONS,POST}'.split(',')}")
  private List<String>                   allowedMethods;

  @Value("#{'${meeds.oauth.cors.allowed-headers:Accept-Encoding,Accept-Language,Accept,Authorization,Cache-Control,Content-Type,Pragma}'.split(',')}")
  private List<String>                   allowedHeaders;

  @Value("#{'${meeds.oauth.cors.exposed-headers:Cache-Control,Content-Language,Content-Type,Expires,Last-Modified,Pragma}'.split(',')}")
  private List<String>                   exposedHeaders;

  @Value("#{'${meeds.oauth.cors.path-patterns:/.well-known/**,/connect/**,/oauth2/**,/userinfo}'.split(',')}")
  private List<String>                   paths;

  private Map<String, List<String>>      allowedMethodsByPath = new ConcurrentHashMap<>();

  private Map<String, List<String>>      allowedHeadersByPath = new ConcurrentHashMap<>();

  private Map<String, List<String>>      exposedHeadersByPath = new ConcurrentHashMap<>();

  private List<PathPattern>              pathPatterns;

  private UrlPathHelper                  urlPathHelper        = UrlPathHelper.defaultInstance;

  private PathMatcher                    pathMatcher          = new AntPathMatcher();

  private Map<String, Boolean>           allowedOrigins       = new ConcurrentHashMap<>();

  @PostConstruct
  public void init() {
    EVENT_TYPES.forEach(n -> listenerService.addListener(n,
                                                         e -> this.allowedOrigins.clear()));
  }

  @Override
  public CorsConfiguration getCorsConfiguration(HttpServletRequest request) {
    String origin = request.getHeader(HttpHeaders.ORIGIN);
    PathPattern pathPattern = getAllowedPathPattern(origin, request);
    if (pathPattern == null) {
      return null;
    } else {
      return getConfig(origin, pathPattern.getPatternString());
    }
  }

  public void addPaths(String... paths) {
    if (paths != null && paths.length > 0) {
      this.paths = new ArrayList<>(this.paths);
      Arrays.stream(paths)
            .filter(t -> !this.paths.contains(t))
            .forEach(this.paths::add);
      this.pathPatterns = null;
    }
  }

  public void addExposedHeaders(String path, String... exposedHeaders) {
    if (exposedHeaders != null && exposedHeaders.length > 0) {
      List<String> headers = exposedHeadersByPath.computeIfAbsent(path, k -> new ArrayList<>(this.exposedHeaders));
      Arrays.stream(exposedHeaders)
            .filter(t -> !headers.contains(t))
            .forEach(headers::add);
    }
  }

  public void addAllowedHeaders(String path, String... allowedHeaders) {
    if (allowedHeaders != null && allowedHeaders.length > 0) {
      List<String> headers = this.allowedHeadersByPath.computeIfAbsent(path, k -> new ArrayList<>(this.allowedHeaders));
      Arrays.stream(allowedHeaders)
            .filter(t -> !headers.contains(t))
            .forEach(headers::add);
    }
  }

  public void addAllowedMethods(String path, String... allowedMethods) {
    if (allowedMethods != null && allowedMethods.length > 0) {
      List<String> methods = allowedMethodsByPath.computeIfAbsent(path, k -> new ArrayList<>(this.allowedMethods));
      Arrays.stream(allowedMethods)
            .filter(t -> !methods.contains(t))
            .forEach(methods::add);
    }
  }

  public List<PathPattern> getPathPatterns() {
    if (pathPatterns == null) {
      pathPatterns = paths.stream()
                          .map(PATTERN_PARSER::parse)
                          .toList();
    }
    return pathPatterns;
  }

  /**
   * A redirect URI authorizes CORS only for its own origin: the URI is the
   * origin itself or starts with the origin followed by a path separator. A bare
   * prefix test would let an Origin header that is a truncation of the allowed
   * host (e.g. 'https://client.co' against 'https://client.com/callback') pass.
   */
  private static boolean isUnderOrigin(String redirectUri, String origin) {
    return redirectUri.equals(origin) || redirectUri.startsWith(origin + "/");
  }

  private PathPattern getAllowedPathPattern(String origin, HttpServletRequest request) {
    String uri = request.getRequestURI();
    if (StringUtils.isBlank(origin)
        || uri.startsWith("/oauth2/authorize")) {
      return null;
    } else {
      PathPattern pathPattern = getMatchedPathPattern(request);
      if (pathPattern == null) {
        return null;
      } else if (oAuthSettingService.isAllowAllOrigins()
                 || (CollectionUtils.isNotEmpty(oAuthSettingService.getAllowedOrigins())
                     && oAuthSettingService.getAllowedOrigins().stream().anyMatch(o -> o.equals(origin)))
                 || (CollectionUtils.isNotEmpty(oAuthSettingService.getAllowedRedirectUris())
                     && oAuthSettingService.getAllowedRedirectUris().stream().anyMatch(o -> isUnderOrigin(o, origin)))
                 || oAuthClientService.getClients(false)
                                      .stream()
                                      .filter(c -> c.getRedirectUris() != null)
                                      .flatMap(c -> c.getRedirectUris().stream())
                                      .anyMatch(o -> isUnderOrigin(o, origin))) {
        log.trace("Allowed Cors for Origin '{}' using URI {} and HTTP Method '{}'", origin, uri, request.getMethod());
        return pathPattern;
      } else {
        log.debug("Denied Cors for Origin '{}' using URI {} and HTTP Method '{}'", origin, uri, request.getMethod());
        return null;
      }
    }
  }

  private PathPattern getMatchedPathPattern(HttpServletRequest request) {
    Object requestPath = resolveRequestPath(request);
    boolean isPathContainer = (requestPath instanceof PathContainer);
    return getPathPatterns().stream().filter(p -> matchPath(requestPath, isPathContainer, p)).findFirst().orElse(null);
  }

  private boolean matchPath(Object path, boolean isPathContainer, PathPattern pattern) {
    return (isPathContainer ? pattern.matches((PathContainer) path) :
                            this.pathMatcher.match(pattern.getPatternString(), (String) path));
  }

  private Object resolveRequestPath(HttpServletRequest request) {
    if (ServletRequestPathUtils.hasCachedPath(request)) {
      return ServletRequestPathUtils.getCachedPath(request);
    } else {
      return this.urlPathHelper.getLookupPathForRequest(request);
    }
  }

  private CorsConfiguration getConfig(String allowedOrigin, String path) {
    CorsConfiguration config = new CorsConfiguration();
    config.setAllowedOrigins(List.of(allowedOrigin));
    config.setAllowedMethods(allowedMethodsByPath.getOrDefault(path, allowedMethods));
    config.setAllowedHeaders(allowedHeadersByPath.getOrDefault(path, allowedHeaders));
    config.setExposedHeaders(exposedHeadersByPath.getOrDefault(path, exposedHeaders));
    config.setMaxAge(3600l);
    return config;
  }

}
