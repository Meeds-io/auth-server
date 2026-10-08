/**
 * This file is part of the Meeds project (https://meeds.io/).
 *
 * Copyright (C) 2026 Meeds Association contact@meeds.io
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
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;

import java.io.IOException;
import java.io.OutputStream;
import java.lang.reflect.Field;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.UnknownHostException;
import java.util.List;
import java.util.Set;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicLong;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import org.exoplatform.services.thumbnail.ImageResizeService;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;

import io.meeds.commons.http.HostResolver;
import io.meeds.commons.http.SafeHttpFetcher;
import io.meeds.oauth2.server.util.Utils;

/**
 * Reads a client's declared logo through the platform's guarded fetcher,
 * against a stub HTTP server on loopback: nothing leaves the machine. A logo
 * that is read reaches the image resizing; one that is refused never does, and
 * the stub's request log says whether a request reached it at all.
 */
class OAuthClientServiceLogoFetchTest {

  private static final String  HOST      = "logo.example.org";

  private static final int     MAX_LOGO  = 1024;

  /** The policy's limit, far above the logo's: only the read's own limit can refuse a logo. */
  private static final long    POLICY_MAX_BYTES = 1024L * 1024;

  private static final byte[]  PNG       = new byte[] { (byte) 0x89, 'P', 'N', 'G', '\r', '\n', 0x1A, '\n' };

  private final List<String>   hits      = new CopyOnWriteArrayList<>();

  private final List<String>   lookups   = new CopyOnWriteArrayList<>();

  private volatile HttpHandler handler;

  private HttpServer           server;

  private InetAddress          stub;

  private int                  port;

  private ImageResizeService   imageResizeService;

  /**
   * Starts the stub.
   *
   * @throws Exception when it cannot start
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
    imageResizeService = mock(ImageResizeService.class);
  }

  /**
   * Stops the stub.
   */
  @AfterEach
  void tearDown() {
    server.stop(0);
  }

  /**
   * A logo served by a public host is read and handed to the resizing.
   *
   * @throws Exception when the resizing mock fails
   */
  @Test
  void aLogoIsReadAndResized() throws Exception {
    handler = exchange -> answer(exchange, PNG);
    try (SafeHttpFetcher fetcher = openToTheStub(true)) {
      OAuthClientService service = serviceWith(fetcher);

      service.fetchLogoUrl("client", "http://" + HOST + ":" + port + "/logo.png");
    }
    verify(imageResizeService).scaleImage(PNG, 300, 300, false, true);
    assertEquals(List.of("/logo.png"), hits);
  }

  /**
   * A logo larger than the logo limit is refused, though the policy's own
   * limit is far larger, and never resized; one announcing a huge body is
   * refused before it is downloaded.
   *
   * @throws Exception when the resizing mock fails
   */
  @Test
  void aLogoOverTheLimitIsRefusedBeforeItIsDownloaded() throws Exception {
    AtomicLong written = new AtomicLong();
    handler = exchange -> {
      if ("/large.png".equals(exchange.getRequestURI().getPath())) {
        answer(exchange, new byte[MAX_LOGO * 4]);
        return;
      }
      exchange.sendResponseHeaders(200, 1L << 30);
      byte[] chunk = new byte[64 * 1024];
      try (OutputStream output = exchange.getResponseBody()) {
        while (written.get() < (1L << 30)) {
          output.write(chunk);
          written.addAndGet(chunk.length);
        }
      }
    };
    try (SafeHttpFetcher fetcher = openToTheStub(true)) {
      OAuthClientService service = serviceWith(fetcher);
      assertNull(service.fetchLogoUrl("client", "http://" + HOST + ":" + port + "/large.png"));
      assertNull(service.fetchLogoUrl("client", "http://" + HOST + ":" + port + "/huge.png"));
    }
    verify(imageResizeService, never()).scaleImage(any(), anyInt(), anyInt(), anyBoolean(), anyBoolean());
    assertTrue(written.get() < 16L * 1024 * 1024, "the refused logo was downloaded: " + written.get() + " bytes");
  }

  /**
   * Under the production policy, a logo URL whose host resolves to an internal
   * address is refused by the lookup the connection itself makes, and nothing
   * is read.
   *
   * @throws Exception when the resizing mock fails
   */
  @Test
  void aLogoOnAHostResolvingToABlockedAddressIsRefusedAtConnection() throws Exception {
    InetAddress internal = InetAddress.getByAddress(new byte[] { 10, 0, 0, 5 });
    try (SafeHttpFetcher production = new SafeHttpFetcher(Utils.urlFetchPolicy(MAX_LOGO).resolver(counting(internal)).build())) {
      assertNull(serviceWith(production).fetchLogoUrl("client", "https://" + HOST + "/logo.png"));
    }
    assertEquals(List.of(HOST), lookups, "the connection's own lookup is the one judged");
    verify(imageResizeService, never()).scaleImage(any(), anyInt(), anyInt(), anyBoolean(), anyBoolean());
  }

  /**
   * A logo host resolving to the stub itself — reachable, listening — is
   * refused when internal addresses are not allowed, and the stub never sees
   * the request.
   *
   * @throws Exception when the resizing mock fails
   */
  @Test
  void aLogoOnAReachableInternalHostIsRefusedAtConnection() throws Exception {
    handler = exchange -> answer(exchange, PNG);
    try (SafeHttpFetcher closed = openToTheStub(false)) {
      assertNull(serviceWith(closed).fetchLogoUrl("client", "http://" + HOST + ":" + port + "/logo.png"));
    }
    assertEquals(List.of(HOST), lookups);
    assertTrue(hits.isEmpty(), "the stub must never see the request");
    verify(imageResizeService, never()).scaleImage(any(), anyInt(), anyInt(), anyBoolean(), anyBoolean());
  }

  /**
   * The production policy opened to the stub's scheme and port, the test host
   * resolving to the stub, its limit above the logo's.
   *
   * @param internalAllowed whether internal addresses may be reached
   * @return the fetcher
   */
  private SafeHttpFetcher openToTheStub(boolean internalAllowed) {
    return new SafeHttpFetcher(Utils.urlFetchPolicy(POLICY_MAX_BYTES)
                                    .allowedSchemes(Set.of("http"))
                                    .allowedPorts(Set.of(port))
                                    .resolver(counting(stub))
                                    .internalAddressesAllowed(internalAllowed)
                                    .build());
  }

  /**
   * A service reading logos through a fetcher, with the logo limit of the
   * tests.
   *
   * @param fetcher the fetcher
   * @return the service
   */
  private OAuthClientService serviceWith(SafeHttpFetcher fetcher) {
    OAuthClientService service = new OAuthClientService();
    setField(service, "fetcher", fetcher);
    setField(service, "maxLogoBytes", MAX_LOGO);
    setField(service, "imageResizeService", imageResizeService);
    return service;
  }

  /**
   * A table resolving the test host to an address, recording every lookup.
   *
   * @param address the address
   * @return the resolver
   */
  private HostResolver counting(InetAddress address) {
    return host -> {
      lookups.add(host);
      if (!HOST.equals(host)) {
        throw new UnknownHostException(host);
      }
      return new InetAddress[] { address };
    };
  }

  /**
   * Answers an image.
   *
   * @param exchange the exchange
   * @param body the bytes
   * @throws IOException when the client went away
   */
  private static void answer(HttpExchange exchange, byte[] body) throws IOException {
    exchange.getResponseHeaders().add("Content-Type", "image/png");
    exchange.sendResponseHeaders(200, body.length);
    try (OutputStream output = exchange.getResponseBody()) {
      output.write(body);
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
