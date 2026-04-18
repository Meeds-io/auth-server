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
package io.meeds.oauth2.server.security;

import java.util.Collections;
import java.util.List;

import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.authentication.jaas.JaasGrantedAuthority;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken;
import org.springframework.stereotype.Component;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import org.exoplatform.container.ExoContainerContext;
import org.exoplatform.services.organization.OrganizationService;
import org.exoplatform.services.organization.UserStatus;
import org.exoplatform.services.security.Authenticator;
import org.exoplatform.services.security.ConversationRegistry;
import org.exoplatform.services.security.ConversationState;
import org.exoplatform.services.security.Identity;
import org.exoplatform.services.security.IdentityConstants;
import org.exoplatform.services.security.IdentityRegistry;
import org.exoplatform.services.security.StateKey;
import org.exoplatform.services.security.jaas.UserPrincipal;
import org.exoplatform.services.security.web.HttpSessionStateKey;

import io.meeds.common.ContainerTransactional;

import jakarta.servlet.http.HttpServletRequest;
import lombok.SneakyThrows;

@Component
public class OAuthPortalAuthenticationProvider implements AuthenticationProvider {

  private OrganizationService  organizationService;

  private ConversationRegistry conversationRegistry;

  private IdentityRegistry     identityRegistry;

  private Authenticator        authenticator;

  @Override
  public boolean supports(Class<?> authentication) {
    return PreAuthenticatedAuthenticationToken.class.isAssignableFrom(authentication);
  }

  @Override
  public Authentication authenticate(Authentication authentication) throws AuthenticationException {
    ServletRequestAttributes requestAttributes = (ServletRequestAttributes) RequestContextHolder.currentRequestAttributes();
    return authenticate(requestAttributes);
  }

  public Identity getCurrentIdentity(HttpServletRequest httpRequest) {
    ConversationState state = ConversationState.getCurrent();
    if (state == null) {
      return getCurrentIdentity(httpRequest, httpRequest.getRemoteUser());
    } else {
      return state.getIdentity();
    }
  }

  public boolean isAnonymousUser(Identity identity) {
    return identity == null
           || IdentityConstants.ANONIM.equals(identity.getUserId())
           || (!identity.isMemberOf("/platform/users") && !identity.isMemberOf("/platform/externals"))
           || isDisabledUser(identity.getUserId());
  }

  @ContainerTransactional
  protected Authentication authenticate(ServletRequestAttributes requestAttributes) {
    HttpServletRequest request = requestAttributes.getRequest();
    try {
      Identity identity = getCurrentIdentity(request);
      if (isAnonymousUser(identity)) {
        return new AnonymousAuthenticationToken(IdentityConstants.ANONIM,
                                                IdentityConstants.ANONIM,
                                                Collections.singletonList(new JaasGrantedAuthority("guests",
                                                                                                   new UserPrincipal(IdentityConstants.ANONIM))));
      } else {
        return new PreAuthenticatedAuthenticationToken(identity.getUserId(),
                                                       identity.getUserId(),
                                                       getAuthorities(identity));
      }
    } catch (Exception e) {
      throw new AuthenticationServiceException("An unknown error is encountered while authenticating user", e);
    }
  }

  private Identity getCurrentIdentity(HttpServletRequest httpRequest, String userId) {
    // only if user authenticated, otherwise there is no reason to do anythings
    if (userId != null) {
      StateKey stateKey = new HttpSessionStateKey(httpRequest.getSession());
      ConversationState state = getStateBySessionId(userId, stateKey);
      if (state == null) {
        state = buildState(userId, stateKey);
      }
      return state == null ? null : state.getIdentity();
    } else {
      return new Identity(IdentityConstants.ANONIM);
    }
  }

  private List<? extends GrantedAuthority> getAuthorities(Identity identity) {
    return identity.getRoles()
                   .stream()
                   .map(SimpleGrantedAuthority::new)
                   .toList();
  }

  private ConversationState buildState(String userId, StateKey stateKey) {
    Identity identity = buildIdentity(userId);
    if (identity == null) {
      return null;
    } else {
      return buildState(identity, stateKey);
    }
  }

  private ConversationState buildState(Identity identity, StateKey stateKey) {
    ConversationState state = new ConversationState(identity);
    getConversationRegistry().register(stateKey, state);
    return state;
  }

  @SneakyThrows
  private Identity buildIdentity(String userId) {
    Identity identity = getIdentityRegistry().getIdentity(userId);
    if (identity == null) {
      identity = getAuthenticator().createIdentity(userId);
      getIdentityRegistry().register(identity);
    }
    return identity;
  }

  private ConversationState getStateBySessionId(String userId, StateKey stateKey) {
    ConversationState state = getConversationRegistry().getState(stateKey);
    if (state != null && !userId.equals(state.getIdentity().getUserId())) {
      state = null;
      getConversationRegistry().unregister(stateKey, false);
    }
    return state;
  }

  @SneakyThrows
  private boolean isDisabledUser(String username) {
    return null == getOrganizationService().getUserHandler()
                                           .findUserByName(username, UserStatus.ENABLED);
  }

  private Authenticator getAuthenticator() {
    if (authenticator == null) {
      authenticator = ExoContainerContext.getService(Authenticator.class);
    }
    return authenticator;
  }

  private IdentityRegistry getIdentityRegistry() {
    if (identityRegistry == null) {
      identityRegistry = ExoContainerContext.getService(IdentityRegistry.class);
    }
    return identityRegistry;
  }

  private OrganizationService getOrganizationService() {
    if (organizationService == null) {
      organizationService = ExoContainerContext.getService(OrganizationService.class);
    }
    return organizationService;
  }

  private ConversationRegistry getConversationRegistry() {
    if (conversationRegistry == null) {
      conversationRegistry = ExoContainerContext.getService(ConversationRegistry.class);
    }
    return conversationRegistry;
  }

}
