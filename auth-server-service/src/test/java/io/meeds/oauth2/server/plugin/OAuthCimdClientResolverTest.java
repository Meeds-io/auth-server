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
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.io.OutputStream;
import java.lang.reflect.Field;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.UnknownHostException;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Set;
import java.util.concurrent.CopyOnWriteArrayList;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;

import io.meeds.commons.http.HostResolver;
import io.meeds.commons.http.SafeFetchException;
import io.meeds.commons.http.SafeFetchFailure;
import io.meeds.commons.http.SafeHttpFetcher;
import io.meeds.oauth2.server.model.OAuthCimdClientMetadata;
import io.meeds.oauth2.server.util.Utils;

/**
 * Reads Client ID Metadata Documents through the platform's guarded fetcher,
 * against a stub HTTP server on loopback: nothing leaves the machine. The
 * documents are served under {@code client.example.org}, resolved from a
 * table to the stub. The reads that must succeed run under the production
 * policy opened to the stub — http, its port, internal addresses allowed; the
 * refusals run under the production policy itself, or that policy with only
 * the scheme and port opened, so that the stub is reachable and the guard is
 * what refuses it.
 */
class OAuthCimdClientResolverTest {

  private static final String       HOST             = "client.example.org";

  /**
   * The policy's limit, as large as the logos' in production: far above the
   * documents', so that only the read's own limit can refuse a document.
   */
  private static final long         POLICY_MAX_BYTES = 20L * 1024 * 1024;

  private final List<String>        hits     = new CopyOnWriteArrayList<>();

  private final List<String>        lookups  = new CopyOnWriteArrayList<>();

  private volatile HttpHandler      handler;

  private HttpServer                server;

  private InetAddress               stub;

  private int                       port;

  private String                    clientId;

  private SafeHttpFetcher           fetcher;

  private OAuthCimdClientResolver   resolver;

  /**
   * Starts the stub and a resolver reading through a fetcher opened to it.
   *
   * @throws Exception when the stub cannot start
   */
  @BeforeEach
  void setUp() throws Exception {
    stub = InetAddress.getByAddress(new byte[] { 127, 0, 0, 1 });
    server = HttpServer.create(new InetSocketAddress(stub, 0), 0);
    server.createContext("/", exchange -> {
      hits.add(exchange.getRequestURI().getPath());
      try {
        handler.handle(exchange);
      } catch (IOException e) {
        // the client went away, as a limit test intends
      } finally {
        exchange.close();
      }
    });
    server.start();
    port = server.getAddress().getPort();
    clientId = "http://" + HOST + ":" + port + "/metadata";
    fetcher = new SafeHttpFetcher(Utils.urlFetchPolicy(POLICY_MAX_BYTES)
                                       .allowedSchemes(Set.of("http"))
                                       .allowedPorts(Set.of(port))
                                       .resolver(table(stub))
                                       .internalAddressesAllowed(true)
                                       .build());
    resolver = resolverWith(fetcher);
  }

  /**
   * Stops the stub and the fetcher.
   */
  @AfterEach
  void tearDown() {
    fetcher.close();
    server.stop(0);
  }

  /**
   * A document served for its own {@code client_id} is read and parsed, and
   * the request asks for JSON.
   */
  @Test
  void resolveShouldFetchAndValidateCimdMetadata() {
    List<String> accepts = new CopyOnWriteArrayList<>();
    handler = exchange -> {
      accepts.add(exchange.getRequestHeaders().getFirst("Accept"));
      json(exchange, """
          {
            "client_id": "%s",
            "client_name": "CIMD Client",
            "client_uri": "https://client.example.org",
            "logo_uri": "https://client.example.org/logo.png",
            "policy_uri": "https://client.example.org/policy",
            "redirect_uris": ["https://client.example.org/callback"],
            "grant_types": ["authorization_code"],
            "response_types": ["code"],
            "scope": "openid profile",
            "token_endpoint_auth_method": "private_key_jwt",
            "jwks_uri": "https://client.example.org/jwks.json"
          }
          """.formatted(clientId));
    };

    OAuthCimdClientMetadata metadata = resolver.resolve(clientId);

    assertEquals(clientId, metadata.clientId());
    assertEquals("CIMD Client", metadata.clientName());
    assertEquals("https://client.example.org", metadata.clientUri());
    assertEquals("https://client.example.org/logo.png", metadata.logoUri());
    assertEquals("https://client.example.org/policy", metadata.policyUri());
    assertEquals("private_key_jwt", metadata.tokenEndpointAuthMethod());
    assertEquals("https://client.example.org/jwks.json", metadata.jwksUri());
    assertEquals("https://client.example.org/callback", metadata.redirectUris().get(0));
    assertEquals(List.of("/metadata"), hits);
    assertEquals(List.of("application/json"), accepts);
  }

  /**
   * A document naming another {@code client_id} is refused.
   */
  @Test
  void resolveShouldRejectClientIdMismatch() {
    handler = exchange -> json(exchange, """
        {
          "client_id": "https://other.example.org/metadata",
          "redirect_uris": ["https://client.example.org/callback"],
          "grant_types": ["authorization_code"],
          "response_types": ["code"],
          "token_endpoint_auth_method": "none"
        }
        """);

    IllegalStateException exception = assertThrows(IllegalStateException.class, () -> resolver.resolve(clientId));

    assertEquals("metadata.client_id must exactly match the client_id URL", exception.getMessage());
  }

  /**
   * A document without redirect URIs is refused.
   */
  @Test
  void resolveShouldRejectEmptyRedirectUris() {
    handler = exchange -> json(exchange, """
        {
          "client_id": "%s",
          "redirect_uris": [],
          "grant_types": ["authorization_code"],
          "response_types": ["code"],
          "token_endpoint_auth_method": "none"
        }
        """.formatted(clientId));

    IllegalStateException exception = assertThrows(IllegalStateException.class, () -> resolver.resolve(clientId));

    assertTrue(exception.getMessage().startsWith("Invalid CIMD JSON document:"));
  }

  /**
   * A {@code private_key_jwt} client without a {@code jwks_uri} is refused.
   */
  @Test
  void resolveShouldRejectPrivateKeyJwtWithoutJwksUri() {
    handler = exchange -> json(exchange, """
        {
          "client_id": "%s",
          "redirect_uris": ["https://client.example.org/callback"],
          "grant_types": ["authorization_code"],
          "response_types": ["code"],
          "token_endpoint_auth_method": "private_key_jwt"
        }
        """.formatted(clientId));

    IllegalStateException exception = assertThrows(IllegalStateException.class, () -> resolver.resolve(clientId));

    assertEquals("jwks_uri is required for 'private_key_jwt' token_endpoint_auth_method", exception.getMessage());
  }

  /**
   * A {@code none} client with a {@code jwks_uri} is refused.
   */
  @Test
  void resolveShouldRejectNoneAuthenticationWithJwksUri() {
    handler = exchange -> json(exchange, """
        {
          "client_id": "%s",
          "redirect_uris": ["https://client.example.org/callback"],
          "grant_types": ["authorization_code"],
          "response_types": ["code"],
          "token_endpoint_auth_method": "none",
          "jwks_uri": "https://client.example.org/jwks.json"
        }
        """.formatted(clientId));

    IllegalStateException exception = assertThrows(IllegalStateException.class, () -> resolver.resolve(clientId));

    assertEquals("jwks_uri must be empty for 'none' token_endpoint_auth_method", exception.getMessage());
  }

  /**
   * An error status is reported as a failed fetch of that {@code client_id}.
   */
  @Test
  void resolveShouldWrapHttpErrors() {
    handler = exchange -> exchange.sendResponseHeaders(500, -1);

    IllegalStateException exception = assertThrows(IllegalStateException.class, () -> resolver.resolve(clientId));

    assertTrue(exception.getMessage().contains("CIMD fetch for '" + clientId + "' failed"));
    assertEquals(SafeFetchFailure.HTTP_ERROR, failureOf(exception));
  }

  /**
   * A document larger than {@link Utils#CIMD_MAX_BYTES} is refused under a
   * policy whose own limit is far larger.
   */
  @Test
  void resolveShouldRefuseADocumentOverTheLimit() {
    handler = exchange -> json(exchange, " ".repeat((int) Utils.CIMD_MAX_BYTES + 1));

    IllegalStateException exception = assertThrows(IllegalStateException.class, () -> resolver.resolve(clientId));

    assertEquals(SafeFetchFailure.TOO_LARGE, failureOf(exception));
  }

  /**
   * A redirect is not followed: the production policy follows none.
   */
  @Test
  void resolveShouldNotFollowARedirect() {
    handler = exchange -> {
      exchange.getResponseHeaders().add("Location", "/elsewhere");
      exchange.sendResponseHeaders(302, -1);
    };

    IllegalStateException exception = assertThrows(IllegalStateException.class, () -> resolver.resolve(clientId));

    assertEquals(SafeFetchFailure.TOO_MANY_REDIRECTS, failureOf(exception));
    assertEquals(List.of("/metadata"), hits);
  }

  /**
   * A {@code client_id} the production policy does not read is refused before
   * any lookup or request: not a URL, http, another port, a fragment, an IP
   * literal naming an internal address.
   */
  @Test
  void resolveShouldRefuseAClientIdOutsideTheProductionRules() {
    try (SafeHttpFetcher production = new SafeHttpFetcher(Utils.urlFetchPolicy(Utils.CIMD_MAX_BYTES).resolver(counting(stub)).build())) {
      OAuthCimdClientResolver productionResolver = resolverWith(production);
      for (String refused : new String[] { "not a url", "http://client.example.org/metadata", "http://client.example.org:443/metadata", "https://client.example.org:8443/metadata",
          "https://client.example.org/metadata#frag", "https://127.0.0.1/metadata", "https://[::1]/metadata",
          "https://169.254.169.254/latest/meta-data" }) {
        assertThrows(IllegalArgumentException.class, () -> productionResolver.resolve(refused), refused);
      }
    }
    assertTrue(lookups.isEmpty(), "no client_id may be looked up: " + lookups);
    assertTrue(hits.isEmpty());
  }

  /**
   * Under the production policy, a {@code client_id} whose host resolves to an
   * internal address is refused by the lookup the connection itself makes —
   * there is no earlier lookup to disagree with — and no socket is opened.
   */
  @Test
  void resolveShouldRefuseAHostResolvingToABlockedAddressAtConnection() throws Exception {
    InetAddress metadata = InetAddress.getByAddress(new byte[] { (byte) 169, (byte) 254, (byte) 169, (byte) 254 });
    try (SafeHttpFetcher production = new SafeHttpFetcher(Utils.urlFetchPolicy(Utils.CIMD_MAX_BYTES).resolver(counting(metadata)).build())) {
      OAuthCimdClientResolver productionResolver = resolverWith(production);

      IllegalStateException exception = assertThrows(IllegalStateException.class,
                                                     () -> productionResolver.resolve("https://" + HOST + "/metadata"));

      assertEquals(SafeFetchFailure.REFUSED_ADDRESS, failureOf(exception));
    }
    assertEquals(List.of(HOST), lookups, "the connection's own lookup is the one judged");
  }

  /**
   * A host resolving to the stub itself — reachable, listening — is refused
   * when the policy does not allow internal addresses: the guard inside the
   * connection is all that stands between the request and an answer, and the
   * stub never sees the request.
   */
  @Test
  void resolveShouldRefuseAReachableInternalHostAtConnection() {
    handler = exchange -> json(exchange, "{}");
    try (SafeHttpFetcher closed = new SafeHttpFetcher(Utils.urlFetchPolicy(Utils.CIMD_MAX_BYTES)
                                                           .allowedSchemes(Set.of("http"))
                                                           .allowedPorts(Set.of(port))
                                                           .resolver(counting(stub))
                                                           .build())) {
      OAuthCimdClientResolver closedResolver = resolverWith(closed);

      IllegalStateException exception = assertThrows(IllegalStateException.class, () -> closedResolver.resolve(clientId));

      assertEquals(SafeFetchFailure.REFUSED_ADDRESS, failureOf(exception));
    }
    assertEquals(List.of(HOST), lookups);
    assertTrue(hits.isEmpty(), "the stub must never see the request");
  }

  /**
   * A resolver reading through a fetcher.
   *
   * @param fetcherUsed the fetcher
   * @return the resolver
   */
  private static OAuthCimdClientResolver resolverWith(SafeHttpFetcher fetcherUsed) {
    OAuthCimdClientResolver cimdResolver = new OAuthCimdClientResolver();
    setField(cimdResolver, "fetcher", fetcherUsed);
    return cimdResolver;
  }

  /**
   * A table resolving the test host to an address, and nothing else.
   *
   * @param address the address
   * @return the resolver
   */
  private static HostResolver table(InetAddress address) {
    return host -> {
      if (!HOST.equals(host)) {
        throw new UnknownHostException(host);
      }
      return new InetAddress[] { address };
    };
  }

  /**
   * The table above, recording every lookup.
   *
   * @param address the address
   * @return the resolver
   */
  private HostResolver counting(InetAddress address) {
    HostResolver table = table(address);
    return host -> {
      lookups.add(host);
      return table.resolve(host);
    };
  }

  /**
   * The reason the fetch behind a failed resolution failed.
   *
   * @param exception the failure of the resolution
   * @return the fetch's reason
   */
  private static SafeFetchFailure failureOf(IllegalStateException exception) {
    return assertInstanceOf(SafeFetchException.class, exception.getCause()).getFailure();
  }

  /**
   * Answers a JSON body.
   *
   * @param exchange the exchange
   * @param body the body
   * @throws IOException when the client went away
   */
  private static void json(HttpExchange exchange, String body) throws IOException {
    byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
    exchange.getResponseHeaders().add("Content-Type", "application/json");
    exchange.sendResponseHeaders(200, bytes.length);
    try (OutputStream output = exchange.getResponseBody()) {
      output.write(bytes);
    }
  }

  /**
   * Sets a private field.
   *
   * @param target the object
   * @param fieldName the field
   * @param value the value
   */
  private static void setField(Object target, String fieldName, Object value) {
    try {
      Field field = target.getClass().getDeclaredField(fieldName);
      field.setAccessible(true); // NOSONAR
      field.set(target, value); // NOSONAR
    } catch (ReflectiveOperationException e) {
      throw new IllegalStateException(e);
    }
  }
}
