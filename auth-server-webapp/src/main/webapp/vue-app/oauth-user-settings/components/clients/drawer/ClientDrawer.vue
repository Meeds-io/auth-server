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
    id="OAuthUserSettingsClientDrawer"
    ref="drawer"
    v-model="drawer"
    :loading="loading"
    allow-expand
    no-x-scroll
    right>
    <template #title>
      {{ $t('UserSettings.oauth.client.drawerTitle') }}
    </template>
    <template v-if="drawer" #content>
      <div class="pa-5">
        <div class="d-flex flex-nowrap align-center mb-4">
          <v-avatar
            class="me-4"
            size="40"
            tile>
            <v-img
              v-if="client.logoUrl"
              :src="client.logoUrl"
              transition="none"
              width="40"
              max-height="40"
              contain
              eager />
            <v-icon
              v-else
              size="40">
              fa-key
            </v-icon>
          </v-avatar>
          <v-card
            class="d-flex flex-column justify-center text-start text-truncate flex-grow-1"
            height="40"
            flat>
            {{ client.name }}
          </v-card>
        </div>
        <div v-if="consent">
          <div v-if="createdDate" class="d-flex align-center mb-2">
            {{ $t('UserSettings.oauth.client.startedUsingAt') }}
            <date-format
              :value="createdDate"
              :format="fullDateFormat"
              class="text-body ms-2" />
          </div>
          <div v-if="lastUsageDate" class="d-flex align-center mb-2">
            {{ $t('UserSettings.oauth.client.lastUsageSince') }}
            <relative-date-format
              :value="lastUsageDate"
              class="text-body ms-2" />
          </div>
          <div class="text-header d-flex align-center my-4">
            {{ $t('UserSettings.oauth.client.authorizedScopes') }}
            <v-btn
              :title="$t('UserSettings.oauth.client.delete')"
              color="error"
              class="ms-2"
              icon
              small
              @click="$emit('delete', client.uuid)">
              <v-icon size="16">fa-trash</v-icon>
            </v-btn>
          </div>
          <div
            v-for="scope in authorizedScopes"
            :key="scope"
            class="mb-2">
            {{ $t(`oAuthConsent.scope.${scope}.name`) }}
          </div>
        </div>
        <v-alert
          v-else
          type="info"
          icon="fa-info-circle"
          class="mt-8"
          outlined>
          {{ $t('UserSettings.oauth.client.notConnectedPlaceholder') }}
          <a
            v-if="client.url"
            :href="client.url"
            :aria-label="$t('UserSettings.oauth.visitWebsite')"
            rel="nofollow noreferrer noopener"
            target="_blank"
            class="d-flex mt-4">
            {{ $t('UserSettings.oauth.visitWebsite') }}
            <v-icon size="12" class="text-link ms-1">fa-external-link-alt</v-icon>
          </a>
        </v-alert>
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
    consents: {
      type: Array,
      default: null,
    },
  },
  data: () => ({
    drawer: false,
    client: null,
    lastUsageDate: null,
    fullDateFormat: {
      day: 'numeric',
      month: 'short',
      year: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
    }
  }),
  computed: {
    consentsByClient() {
      return this.clients && this.consents && Object.fromEntries(this.clients?.map?.(c => [c.uuid, this.consents?.find?.(co => co.clientId === c.id)])) || {};
    },
    consent() {
      return this.consentsByClient?.[this.client?.uuid];
    },
    createdDate() {
      return this.consent?.createdDate;
    },
    authorizedScopes() {
      return this.consent?.scopes?.map?.(s => s.replace('SCOPE_', ''))?.sort?.((a, b) => {
        if (a === 'openid') {
          return -1;
        } else if (b === 'openid') {
          return 1;
        } else if (a.includes('read') && !b.includes('read')) {
          return -1;
        } else if (b.includes('read') && !a.includes('read')) {
          return 1;
        } else {
          return a.localeCompare(b);
        }
      });
    },
  },
  methods: {
    async open(client) {
      this.client = client;
      this.$refs.drawer.open();
      try {
        this.lastUsageDate = await this.$oAuthClientService.getClientLastUsage(this.client.uuid, eXo.env.portal.userName);
      } catch {
        this.lastUsageDate = null;
      }
    },
    close() {
      this.$refs.drawer.close();
    },
  },
};
</script>
