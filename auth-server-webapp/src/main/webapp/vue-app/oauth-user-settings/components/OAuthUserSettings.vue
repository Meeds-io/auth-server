<!--
 This file is part of the Meeds project (https://meeds.io/).

 Copyright (C) 2020 - 2026 Meeds Association contact@meeds.io

 This program is free software; you can redistribute it and/or
 modify it under the terms of the GNU Lesser General Public
 License as published by the Free Software Foundation; either
 version 3 of the License, or (at your option) any later version.
 This program is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 Lesser General Public License for more details.

 You should have received a copy of the GNU Lesser General Public License
 along with this program; if not, write to the Free Software Foundation,
 Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
-->
<template>
  <v-list-item v-if="displayedClients?.length" dense>
    <v-list-item-content>
      <v-list-item-title>
        {{ $t('UserSettings.oauth.title') }}
      </v-list-item-title>
    </v-list-item-content>
    <v-list-item-action>
      <v-tooltip bottom>
        <template #activator="{on, attrs}">
          <div
            v-on="on"
            v-bind="attrs">
            <v-btn
              :aria-label="$t('UserSettings.oauth.editSettings')"
              small
              icon
              @click="$refs.drawer.open()">
              <v-icon size="18" class="icon-default-color">fa-edit</v-icon>
            </v-btn>
          </div>
        </template>
        <span>{{ $t('UserSettings.oauth.editSettings') }}</span>
      </v-tooltip>  
    </v-list-item-action>
    <oauth-user-settings-drawer
      ref="drawer"
      :clients="displayedClients"
      :tokens="tokens" />
  </v-list-item>
</template>
<script>
export default {
  data: () => ({
    clients: null,
    tokens: null,
    scopes: null,
  }),
  computed: {
    tokensByClient() {
      return this.clients && this.tokens && Object.fromEntries(this.clients?.map?.(c => [c.uuid, this.tokens?.filter?.(t => t.clientId === c.id)])) || {};
    },
    consentsByClient() {
      return this.clients && this.consents && Object.fromEntries(this.clients?.map?.(c => [c.uuid, this.consents?.find?.(co => co.clientId === c.id)])) || {};
    },
    displayedClients() {
      return this.clients?.filter?.(c => c.displayed || this.tokensByClient[c.uuid]?.length || this.consentsByClient[c.uuid]);
    },
  },
  async created() {
    const lang = eXo?.env?.portal?.language;
    [
      this.clients,
      this.consents,
      this.tokens,
    ] = await Promise.all([
      this.$oAuthClientService.getClients(false),
      this.$oAuthConsentService.getConsents(),
      this.$oAuthTokenService.getTokens(),
      exoi18n.loadLanguageAsync(lang, `/auth-server/i18n/locale.portlet.OAuthConsent?lang=${lang}`),
    ]);
  },
};
</script>
