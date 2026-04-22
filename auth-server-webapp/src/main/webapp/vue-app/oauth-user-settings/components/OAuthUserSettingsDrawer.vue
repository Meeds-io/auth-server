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
  <exo-drawer
    id="OAuthSecuritySettingsDrawer"
    ref="drawer"
    v-model="drawer"
    :loading="loading"
    :allow-expand="!expanded"
    no-x-scroll
    right
    @expand-updated="expanded = $event">
    <template #title>
      {{ $t('UserSettings.oauth.drawerTitle') }}
    </template>
    <template v-if="drawer" #content>
      <div class="pa-5">
        <oauth-user-settings-clients
          :clients="clients"
          :scopes="scopes" />
      </div>
    </template>
  </exo-drawer>
</template>
<script>
export default {
  props: {
    clients: {
      type: Array,
      default: null,
    },
  },
  data: () => ({
    drawer: false,
    expanded: false,
    loading: false,
    tokens: null,
    consents: null,
    scopes: null,
    panelIndex: null,
  }),
  computed: {
    tokensByClient() {
      return this.clients && this.tokens && Object.fromEntries(this.clients?.map?.(c => [c.uuid, this.tokens.filter(t => t.clientId === c.id)])) || {};
    },
    consentsByClient() {
      return this.clients && this.consents && Object.fromEntries(this.clients?.map?.(c => [c.uuid, this.consents.find(co => co.clientId === c.id)])) || {};
    },
  },
  watch: {
    expanded() {
      if (!this.expanded) {
        this.$refs.drawer.toogleExpand();
      }
    },
  },
  methods: {
    async open() {
      this.$refs.drawer.open();
      this.loading = true;
      try {
        [
          this.tokens,
          this.consents,
          this.scopes
        ] = await Promise.all([
          this.$oAuthTokenService.getTokens(),
          this.$oAuthConsentService.getConsents(),
          this.$oAuthSettingService.getScopes()
        ]);
        if (!this.expanded) {
          this.$refs.drawer.toogleExpand();
        }
      } finally {
        this.loading = false;
      }
    },
    close() {
      this.$refs.drawer.close();
    },
    async deleteConsentByClient(clientId) {
      this.loading = true;
      try {
        await this.$oAuthConsentService.deleteConsentByUserAndClient(clientId);
        [
          this.tokens,
          this.consents
        ] = await Promise.all([
          this.$oAuthTokenService.getTokens(),
          this.$oAuthConsentService.getConsents()
        ]);
      } finally {
        this.loading = false;
      }
    },
    async deleteTokenById(tokenId) {
      this.loading = true;
      try {
        await this.$oAuthTokenService.deleteTokenById(tokenId);
        this.tokens = await this.$oAuthTokenService.getTokens();
      } finally {
        this.loading = false;
      }
    },
    async deleteTokensByClient(clientId) {
      this.loading = true;
      try {
        await Promise.all(this.tokens
          .filter(t => t.clientId === clientId)
          .map(t => this.$oAuthTokenService.deleteTokenById(t.id)));
        this.tokens = await this.$oAuthTokenService.getTokens();
      } finally {
        this.loading = false;
      }
    },
    async deleteAllTokens() {
      this.loading = true;
      try {
        await Promise.all(this.tokens.map(t => this.$oAuthTokenService.deleteTokenById(t.id)));
      } finally {
        this.loading = false;
      }
    },
  },
};
</script>
