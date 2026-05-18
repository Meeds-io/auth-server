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

import static io.meeds.oauth2.server.util.EntityMapper.CLIENT_ENABLED_SETTING;
import static io.meeds.oauth2.server.util.EntityMapper.CLIENT_IS_CIMD_SETTING;
import static io.meeds.oauth2.server.util.EntityMapper.CLIENT_IS_DCR_SETTING;
import static io.meeds.oauth2.server.util.EntityMapper.CLIENT_LOGO_URI_SETTING;
import static io.meeds.oauth2.server.util.EntityMapper.CLIENT_SYSTEM_SETTING;
import static io.meeds.oauth2.server.util.EntityMapper.CLIENT_URI_SETTING;
import static io.meeds.oauth2.server.util.EntityMapper.CLIENT_UUID_SETTING;

import java.io.IOException;
import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.time.Instant;
import java.util.Collections;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicInteger;

import org.apache.commons.collections4.CollectionUtils;
import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatusCode;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient.Builder;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestClient;

import org.exoplatform.commons.ObjectAlreadyExistsException;
import org.exoplatform.commons.exception.ObjectNotFoundException;
import org.exoplatform.commons.utils.CommonsUtils;
import org.exoplatform.portal.config.UserACL;
import org.exoplatform.services.thumbnail.ImageResizeService;
import org.exoplatform.social.attachment.AttachmentService;
import org.exoplatform.social.attachment.model.FileAttachmentObject;
import org.exoplatform.social.attachment.model.FileAttachmentResourceList;
import org.exoplatform.social.core.manager.IdentityManager;
import org.exoplatform.upload.UploadResource;
import org.exoplatform.upload.UploadService;

import io.meeds.oauth2.server.model.ClientRegistrationRateLimitException;
import io.meeds.oauth2.server.plugin.OAuthClientAttachmentPlugin;
import io.meeds.oauth2.server.plugin.OAuthDcrValidator;
import io.meeds.oauth2.server.storage.OAuthClientStorage;
import io.meeds.oauth2.server.util.Utils;

import lombok.Synchronized;
import lombok.extern.slf4j.Slf4j;

@Service
@Slf4j
public class OAuthClientService {

  public static final String      ATTACHMENT_URL_PATTERN      = "%s/portal/rest/v1/social/attachments/%s/%s/%s";

  private static final String     CLIENT_NAME_MANDATORY_MSG   = "Client Name is mandatory";

  private static final String     CLIENT_ID_MANDATORY_MSG     = "Client Id is mandatory";

  private static final String     CLIENT_NOT_FOUND_MSG        = "Client with Id %s not found";

  private static final String     CLIENT_SYSTEM_MSG           =
                                                    "Client with Id %s can't be removed as it's required by the system";

  private static final String     REDIRECT_URIS_MANDATORY_MSG = "Client Redirect URIs is mandatory";

  private static final String     REDIRECT_NAME_MANDATORY_MSG = "Client Name is mandatory";

  private static final String     SCOPES_MANDATORY_MSG        = "Client Scopes is mandatory";

  private static final int        REGISTER_RATE_SECONDS_COUNT = 60;

  @Autowired
  private RestClient              restClient;

  @Autowired
  private UserACL                 userAcl;

  @Autowired
  private OAuthSettingService     oAuthSettingService;

  @Autowired
  private UploadService           uploadService;

  @Autowired
  private AttachmentService       attachmentService;

  @Autowired
  private IdentityManager         identityManager;

  @Autowired
  private ImageResizeService      imageResizeService;

  @Autowired
  private OAuthClientStorage      storage;

  @Autowired
  private List<OAuthDcrValidator> openRegistrationValidators;

  @Value("${meeds.oauth.selfRegister.enabled:true}")
  private boolean                 selfRegisterEnabled;

  @Value("${meeds.oauth.selfRegister.maxLogoBytes:20971520}")
  private int                     maxLogoBytes;

  @Value("${meeds.oauth.selfRegister.maxRatePerMinute:10}")
  private int                     clientSelfRegisterRate;

  private AtomicInteger           registerCount               = new AtomicInteger();

  private Instant                 lastRegisterCountInstant;

  public List<RegisteredClient> getAllClients() {
    return getClients(true);
  }

  public List<RegisteredClient> getClients(boolean includeDisabled) {
    List<RegisteredClient> clients = storage.findAll();
    if (!includeDisabled) {
      clients = clients.stream()
                       .filter(client -> {
                         Boolean clientEnabled = client.getClientSettings().getSetting(CLIENT_ENABLED_SETTING);
                         return (clientEnabled == null || clientEnabled.booleanValue());
                       })
                       .toList();
    }
    return clients;
  }

  public List<RegisteredClient> getClients(String username, boolean includeDisabled) throws IllegalAccessException {
    if (includeDisabled && !userAcl.isAdministrator(userAcl.getUserIdentity(username))) {
      throw new IllegalAccessException("Not authorized to display all available clients");
    }
    return getClients(includeDisabled);
  }

  public RegisteredClient getClient(String clientId, boolean includeDisabled, String username) throws IllegalAccessException {
    if (includeDisabled && !userAcl.isAdministrator(userAcl.getUserIdentity(username))) {
      throw new IllegalAccessException("Not authorized to display all available clients");
    }
    return getClient(clientId, includeDisabled);
  }

  public RegisteredClient getClient(String clientId, boolean includeDisabled) {
    return storage.getClient(clientId, includeDisabled);
  }

  public RegisteredClient getClient(String clientId) {
    return getClient(clientId, false);
  }

  public RegisteredClient register(RegisteredClient publicClient) throws ClientRegistrationRateLimitException,
                                                                  IllegalAccessException,
                                                                  ObjectNotFoundException {
    if (getAndIncrementRegisterCount() > clientSelfRegisterRate) {
      throw new ClientRegistrationRateLimitException("[DCR / CIMD] Max Clients Self REgister Requests Reached",
                                                     REGISTER_RATE_SECONDS_COUNT - getRateSecondsDiff());
    }
    String clientId = computePublicClientId(publicClient);
    RegisteredClient existingClient = getClient(clientId, true);
    if (existingClient == null) {
      if (!selfRegisterEnabled) {
        throw new IllegalStateException("[DCR / CIMD] Feature is disabled");
      }
      RegisteredClient clientToSave = normalizeClient(clientId, publicClient, existingClient, true);

      // Only allowed Redirect URIs will be able to self register as public
      // client Validation is necessary only when modification will made on
      // the
      // store
      openRegistrationValidators.forEach(r -> r.validate(clientToSave));

      // Allow creation Only on Self-Registration
      saveClient(clientToSave);
      updateClientActivation(clientToSave.getClientId(), true);
      log.info("Self Register Client: '{}'", clientToSave);
    } else {
      // No modifications allowed since only Public clients is allowed, just
      // logging
      publicClient.getRedirectUris()
                  .stream()
                  .filter(u -> !existingClient.getRedirectUris().contains(u))
                  .forEach(u -> log.warn("[DCR / CIMD] Self Registered Client '{}': Redirect URI '{}' appending ignored",
                                         existingClient.getClientName(),
                                         u));
      publicClient.getScopes()
                  .stream()
                  .filter(s -> !existingClient.getScopes().contains(s))
                  .forEach(s -> log.warn("[DCR / CIMD] Self Registered Client '{}': Scope '{}' appending ignored",
                                         existingClient.getClientName(),
                                         s));
    }
    RegisteredClient client = getClient(clientId, false);
    if (client == null
        || !client.getAuthorizationGrantTypes().contains(AuthorizationGrantType.AUTHORIZATION_CODE)
        || client.getAuthorizationGrantTypes().contains(AuthorizationGrantType.JWT_BEARER)
        || (client.getAuthorizationGrantTypes().contains(AuthorizationGrantType.CLIENT_CREDENTIALS)
            && !Objects.equals(client.getClientSettings().getSetting(CLIENT_IS_CIMD_SETTING), true)
            && !Objects.equals(client.getClientSettings().getSetting(CLIENT_IS_DCR_SETTING), true))
        || !client.getClientSettings().isRequireAuthorizationConsent()
        || !client.getClientSettings().isRequireProofKey()) {
      throw new IllegalStateException("[DCR / CIMD] Self Registered Client not enabled");
    }
    return client;
  }

  public RegisteredClient createClient(RegisteredClient client) throws ObjectAlreadyExistsException {
    if (client == null) {
      throw new IllegalArgumentException("Client is null");
    }
    if (CollectionUtils.isEmpty(client.getRedirectUris())) {
      throw new IllegalArgumentException(REDIRECT_URIS_MANDATORY_MSG);
    }
    if (StringUtils.isBlank(client.getClientId())) {
      throw new IllegalArgumentException(CLIENT_ID_MANDATORY_MSG);
    }
    if (StringUtils.isBlank(client.getClientName())) {
      throw new IllegalArgumentException(CLIENT_NAME_MANDATORY_MSG);
    }
    if (getClient(client.getClientId(), true) != null) {
      throw new ObjectAlreadyExistsException("A client with id '%s' already exists".formatted(client.getClientId()));
    }
    boolean isPublicClient = client.getClientAuthenticationMethods().contains(ClientAuthenticationMethod.NONE);

    boolean shouldApplyPublicDefaults = Objects.equals(client.getClientSettings().getSetting(CLIENT_IS_CIMD_SETTING), true)
                                        || Objects.equals(client.getClientSettings().getSetting(CLIENT_IS_DCR_SETTING), true)
                                        || isPublicClient;
    RegisteredClient clientToCreate = normalizeClient(client.getClientId(), client, null, shouldApplyPublicDefaults);
    saveClient(clientToCreate);
    return getClient(client.getClientId(), true);
  }

  public void deleteClient(String clientId) throws ObjectNotFoundException, IllegalAccessException {
    if (StringUtils.isBlank(clientId)) {
      throw new IllegalArgumentException(CLIENT_ID_MANDATORY_MSG);
    }
    RegisteredClient client = checkClientExists(clientId);
    checkSystem(client);
    storage.delete(clientId);
  }

  public void updateClient(RegisteredClient client) throws ObjectNotFoundException, IllegalAccessException {
    if (client == null) {
      throw new IllegalArgumentException("Client is null");
    }
    String clientId = client.getClientId();
    if (StringUtils.isBlank(clientId)) {
      throw new IllegalArgumentException(CLIENT_ID_MANDATORY_MSG);
    }
    if (CollectionUtils.isEmpty(client.getRedirectUris())) {
      throw new IllegalArgumentException(REDIRECT_URIS_MANDATORY_MSG);
    }
    if (StringUtils.isBlank(client.getClientName())) {
      throw new IllegalArgumentException(CLIENT_NAME_MANDATORY_MSG);
    }
    RegisteredClient existingClient = checkClientExists(clientId);
    checkSystem(existingClient);
    RegisteredClient clientToUpdate = normalizeClient(clientId, client, existingClient, false);
    saveClient(clientToUpdate);
  }

  public void updateClientName(String clientId, String name) throws ObjectNotFoundException, IllegalAccessException {
    if (StringUtils.isBlank(clientId)) {
      throw new IllegalArgumentException(CLIENT_ID_MANDATORY_MSG);
    }
    if (StringUtils.isBlank(name)) {
      throw new IllegalArgumentException(REDIRECT_NAME_MANDATORY_MSG);
    }
    RegisteredClient existingClient = checkClientExists(clientId);
    checkSystem(existingClient);
    RegisteredClient clientToUpdate = RegisteredClient.from(existingClient)
                                                      .clientName(name)
                                                      .build();
    saveClient(clientToUpdate);
  }

  public void updateClientUrl(String clientId, String url) throws ObjectNotFoundException, IllegalAccessException {
    if (StringUtils.isBlank(clientId)) {
      throw new IllegalArgumentException(CLIENT_ID_MANDATORY_MSG);
    }
    RegisteredClient existingClient = checkClientExists(clientId);
    checkSystem(existingClient);
    RegisteredClient clientToUpdate = RegisteredClient.from(existingClient)
                                                      .clientSettings(ClientSettings.withSettings(existingClient.getClientSettings()
                                                                                                                .getSettings())
                                                                                    .settings(settings -> {
                                                                                      if (StringUtils.isBlank(url)) {
                                                                                        settings.remove(CLIENT_URI_SETTING);
                                                                                      } else {
                                                                                        settings.put(CLIENT_URI_SETTING, url);
                                                                                      }
                                                                                    })
                                                                                    .build())
                                                      .build();
    saveClient(clientToUpdate);
  }

  public void updateClientLogoUrl(String clientId, String logoUrl) throws ObjectNotFoundException, IllegalAccessException {
    if (StringUtils.isBlank(clientId)) {
      throw new IllegalArgumentException(CLIENT_ID_MANDATORY_MSG);
    }
    RegisteredClient existingClient = checkClientExists(clientId);
    checkSystem(existingClient);
    RegisteredClient clientToUpdate = RegisteredClient.from(existingClient)
                                                      .clientSettings(ClientSettings.withSettings(existingClient.getClientSettings()
                                                                                                                .getSettings())
                                                                                    .settings(settings -> {
                                                                                      if (StringUtils.isBlank(logoUrl)) {
                                                                                        settings.remove(CLIENT_LOGO_URI_SETTING);
                                                                                      } else {
                                                                                        settings.put(CLIENT_LOGO_URI_SETTING,
                                                                                                     logoUrl);
                                                                                      }
                                                                                    })
                                                                                    .build())
                                                      .build();
    saveClient(clientToUpdate);
  }

  public void updateClientRedirectUris(String clientId, Set<String> redirectUris) throws ObjectNotFoundException,
                                                                                  IllegalAccessException {
    if (StringUtils.isBlank(clientId)) {
      throw new IllegalArgumentException(CLIENT_ID_MANDATORY_MSG);
    }
    if (CollectionUtils.isEmpty(redirectUris)) {
      throw new IllegalArgumentException(REDIRECT_URIS_MANDATORY_MSG);
    }
    RegisteredClient existingClient = checkClientExists(clientId);
    checkSystem(existingClient);
    RegisteredClient clientToUpdate = RegisteredClient.from(existingClient)
                                                      .redirectUris(r -> {
                                                        r.clear();
                                                        r.addAll(redirectUris);
                                                      })
                                                      .build();
    saveClient(clientToUpdate);
  }

  public void updateClientScopes(String clientId, Set<String> scopes) throws ObjectNotFoundException, IllegalAccessException {
    if (StringUtils.isBlank(clientId)) {
      throw new IllegalArgumentException(CLIENT_ID_MANDATORY_MSG);
    }
    if (CollectionUtils.isEmpty(scopes)) {
      throw new IllegalArgumentException(SCOPES_MANDATORY_MSG);
    }
    RegisteredClient existingClient = checkClientExists(clientId);
    checkSystem(existingClient);
    RegisteredClient clientToUpdate = RegisteredClient.from(existingClient)
                                                      .scopes(r -> {
                                                        r.clear();
                                                        r.add(OidcScopes.OPENID);
                                                        r.add(Utils.OFFLINE_ACCESS_SCOPE);
                                                        r.addAll(scopes);
                                                      })
                                                      .build();
    saveClient(clientToUpdate);
  }

  public void updateClientVisibility(String clientId, boolean displayed) throws ObjectNotFoundException, IllegalAccessException {
    RegisteredClient existingClient = checkClientExists(clientId);
    checkSystem(existingClient);
    if (displayed) {
      storage.display(clientId);
    } else {
      storage.hide(clientId);
    }
  }

  public void updateClientActivation(String clientId, boolean enabled) throws ObjectNotFoundException, IllegalAccessException {
    RegisteredClient existingClient = checkClientExists(clientId);
    checkSystem(existingClient);
    if (enabled) {
      storage.enable(clientId);
    } else {
      storage.disable(clientId);
    }
  }

  public void saveClient(RegisteredClient registeredClient) {
    RegisteredClient existingClient = storage.getClient(registeredClient.getClientId(), true);
    if (existingClient == null) {
      storage.save(registeredClient);
    } else {
      storage.save(RegisteredClient.from(registeredClient)
                                   .id(existingClient.getId())
                                   .clientId(existingClient.getClientId())
                                   .build());
    }
  }

  private RegisteredClient checkClientExists(String clientId) throws ObjectNotFoundException {
    RegisteredClient client = getClient(clientId, true);
    if (client == null) {
      throw new ObjectNotFoundException(CLIENT_NOT_FOUND_MSG.formatted(clientId));
    }
    return client;
  }

  private void checkSystem(RegisteredClient client) throws IllegalAccessException {
    boolean system = client.getClientSettings().getSetting(CLIENT_SYSTEM_SETTING) != null
                     && Boolean.parseBoolean(client.getClientSettings()
                                                   .getSetting(CLIENT_SYSTEM_SETTING)
                                                   .toString());
    if (system) {
      throw new IllegalAccessException(CLIENT_SYSTEM_MSG.formatted(client.getClientId()));
    }
  }

  private String computePublicClientId(RegisteredClient publicClient) {
    RegisteredClient existingClient = getClients(false).stream()
                                                       .filter(c -> publicClient.getRedirectUris()
                                                                                .stream()
                                                                                .allMatch(u -> c.getRedirectUris()
                                                                                                .contains(u)))
                                                       .findFirst()
                                                       .orElse(null);
    if (existingClient == null) {
      return publicClient.getClientId();
    } else {
      return existingClient.getClientId();
    }
  }

  private RegisteredClient normalizeClient(String clientId,
                                           RegisteredClient client,
                                           RegisteredClient existingClient,
                                           boolean applyPublicClientSettings) {
    Builder clientBuilder;
    if (existingClient != null) {
      clientBuilder = RegisteredClient.from(existingClient)
                                      .scopes(s -> s.addAll(client.getScopes()));
    } else {
      clientBuilder = RegisteredClient.from(client)
                                      .id(clientId)
                                      .clientId(clientId)
                                      .clientIdIssuedAt(Instant.now())
                                      .scopes(scopes -> {
                                        scopes.remove(OidcScopes.OPENID);
                                        scopes.remove(Utils.OFFLINE_ACCESS_SCOPE);
                                        if (CollectionUtils.isEmpty(scopes)) {
                                          scopes.addAll(oAuthSettingService.getScopes());
                                        } else {
                                          scopes.add(OidcScopes.OPENID);
                                          scopes.add(Utils.OFFLINE_ACCESS_SCOPE);
                                          scopes.retainAll(oAuthSettingService.getScopes());
                                        }
                                      });
    }
    if (applyPublicClientSettings) {
      applyPublicClientSettings(client, existingClient, clientBuilder);
    }
    return clientBuilder.clientName(client.getClientName())
                        .redirectUris(uris -> uris.addAll(client.getRedirectUris()))
                        .build();
  }

  private void applyPublicClientSettings(RegisteredClient client,
                                         RegisteredClient existingClient,
                                         Builder clientBuilder) {
    TokenSettings publicClientTokenSettings = oAuthSettingService.getPublicClientTokenSettings();
    ClientSettings publicClientSettings = getPublicClientSettings(client, existingClient);
    clientBuilder.clientSettings(publicClientSettings)
                 .tokenSettings(publicClientTokenSettings)
                 .scope(OidcScopes.OPENID)
                 .scope(Utils.OFFLINE_ACCESS_SCOPE);
  }

  private ClientSettings getPublicClientSettings(RegisteredClient client, RegisteredClient existingClient) {
    ClientSettings.Builder clientSettingsBuilder = ClientSettings.withSettings(client.getClientSettings()
                                                                                     .getSettings());
    // Copy Existing Client Settings
    String clientId = client.getClientId();
    if (existingClient != null) {
      // Avoid to publically modify an existing Client Setting
      existingClient.getClientSettings()
                    .getSettings()
                    .forEach(clientSettingsBuilder::setting);
    } else if (clientId.contains("/")) {
      clientId = UUID.randomUUID().toString();
      clientSettingsBuilder.setting(CLIENT_UUID_SETTING, clientId);
    }

    // Apply General Public Client Settings
    oAuthSettingService.getPublicClientSettings()
                       .getSettings()
                       .forEach(clientSettingsBuilder::setting);

    // Download Logo And serve it from local URL
    String logoUrl = client.getClientSettings().getSetting(CLIENT_LOGO_URI_SETTING);
    if (StringUtils.isNotBlank(logoUrl)
        && !logoUrl.startsWith(CommonsUtils.getCurrentDomain())) {
      String fetchedLogoUrl = fetchLogoUrl(clientId, logoUrl);
      clientSettingsBuilder.settings(settings -> {
        if (StringUtils.isBlank(fetchedLogoUrl)) {
          // Remove Logo URL when error
          settings.remove(CLIENT_LOGO_URI_SETTING);
        } else {
          settings.put(CLIENT_LOGO_URI_SETTING, fetchedLogoUrl);
        }
      });
    }

    return clientSettingsBuilder.build();
  }

  private String fetchLogoUrl(String clientId, String url) {
    try {
      URI uri = Utils.validateUrl(url);
      byte[] imageBytes = restClient.get()
                                    .uri(uri)
                                    .header("Accept", "image/png,image/jpeg,image/webp")
                                    .retrieve()
                                    .onStatus(HttpStatusCode::isError, (req, res) -> {
                                      throw new IllegalArgumentException("Remote server returned " + res.getStatusCode());
                                    })
                                    .body(byte[].class);
      if (imageBytes == null || imageBytes.length == 0) {
        throw new IllegalArgumentException("Empty response");
      } else if (imageBytes.length > maxLogoBytes) {
        throw new IllegalArgumentException("Image too large");
      } else {
        byte[] resizedImageBytes = imageResizeService.scaleImage(imageBytes,
                                                                 300,
                                                                 300,
                                                                 false,
                                                                 true);
        return createImageAttachment(clientId, resizedImageBytes);
      }
    } catch (Exception e) {
      log.warn("Error while computing OAuth Client Logo URL for client '{}' and url '{}'. Use empty logo URL instead.",
               clientId,
               url,
               e);
      return null;
    }
  }

  private String createImageAttachment(String clientId, byte[] imageBytes) throws IOException {
    String uploadId = createUploadResource(imageBytes);
    try {
      FileAttachmentObject fileAttachmentObject = new FileAttachmentObject();
      fileAttachmentObject.setUploadId(uploadId);
      FileAttachmentResourceList fileAttachmentResourceList = new FileAttachmentResourceList();
      fileAttachmentResourceList.setUserIdentityId(getSuperAdminIdentityId());
      fileAttachmentResourceList.setUploadedFiles(List.of(fileAttachmentObject));
      fileAttachmentResourceList.setAttachedFiles(Collections.emptyList());
      fileAttachmentResourceList.setObjectType(OAuthClientAttachmentPlugin.OBJECT_TYPE);
      fileAttachmentResourceList.setObjectId(clientId);
      attachmentService.saveAttachments(fileAttachmentResourceList);
      List<String> fileIds = attachmentService.getAttachmentFileIds(OAuthClientAttachmentPlugin.OBJECT_TYPE,
                                                                    clientId);
      return ATTACHMENT_URL_PATTERN.formatted(CommonsUtils.getCurrentDomain(),
                                              OAuthClientAttachmentPlugin.OBJECT_TYPE,
                                              clientId,
                                              fileIds.getLast());
    } finally {
      uploadService.removeUploadResource(uploadId);
    }
  }

  private String createUploadResource(byte[] fileBytes) throws IOException {
    Path file = createTempFile(fileBytes);
    String uploadId = UUID.randomUUID().toString();
    UploadResource uploadResource = new UploadResource(uploadId,
                                                       "image.png",
                                                       "image/png",
                                                       file.toFile().getAbsolutePath(),
                                                       0,
                                                       0,
                                                       UploadResource.UPLOADED_STATUS);
    uploadService.createUploadResource(uploadResource);
    return uploadId;
  }

  private Path createTempFile(byte[] decodedBytes) throws IOException {
    Path tempFile = Files.createTempFile("", "");
    Files.write(tempFile, decodedBytes);
    return tempFile;
  }

  private long getSuperAdminIdentityId() {
    return identityManager.getOrCreateUserIdentity(userAcl.getSuperUser()).getIdentityId();
  }

  @Synchronized
  private int getAndIncrementRegisterCount() {
    if (lastRegisterCountInstant == null || getRateSecondsDiff() >= REGISTER_RATE_SECONDS_COUNT) {
      lastRegisterCountInstant = Instant.now();
      registerCount.set(0);
    }
    return registerCount.incrementAndGet();
  }

  private long getRateSecondsDiff() {
    return lastRegisterCountInstant == null ? 0l : Duration.between(lastRegisterCountInstant, Instant.now()).getSeconds();
  }

}
