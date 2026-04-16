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
  <v-expansion-panel
    :class="!expanded && !lastElement && 'no-border-bottom'"
    class="border-color">
    <v-expansion-panel-header>
      <div class="d-flex flex-nowrap align-center">
        <v-avatar
          v-if="client.logoUrl"
          class="py-0 ps-0 pe-4"
          size="75"
          tile>
          <v-img :src="client.logoUrl" contain />
        </v-avatar>
        <div>
          <v-card-title class="text-header pt-0 ps-0">
            {{ client.name }}
          </v-card-title>
          <v-card-subtitle v-if="client.url" class="ps-0 pb-0">
            <a
              :href="client.url"
              :aria-label="$t('oAuthConsent.visitWebsite')"
              rel="nofollow noreferrer noopener"
              target="_blank"
              class="d-flex">
              {{ $t('oAuthConsent.visitWebsite') }}
              <v-icon size="12" class="text-link ms-1">fa-external-link-alt</v-icon>
            </a>
          </v-card-subtitle>
        </div>
        <template v-if="!expanded">
          <v-spacer />
          <v-chip v-if="consent" class="my-auto me-2 hidden-xs-only">
            <v-icon
              color="success"
              class="me-2 ms-n2"
              size="24">
              fa-check-circle
            </v-icon>
            {{ $t('UserSettings.oauth.consented') }}
          </v-chip>
          <v-chip v-if="tokens?.length" class="my-auto me-2 hidden-xs-only">
            <v-icon
              color="success"
              class="me-2 ms-n1 fa-rotate-270"
              size="18">
              fa-key
            </v-icon>
            <span>{{ $t('UserSettings.oauth.clientHasTokens') }}</span>
          </v-chip>
        </template>
      </div>
    </v-expansion-panel-header>
    <v-expansion-panel-content>
      <div v-if="consent" class="d-flex flex-nowrap align-center">
        <v-card-title class="text-header align-center pa-0">
          {{ $t('UserSettings.oauth.allowedScopesAt') }}
        </v-card-title>
        <date-format
          :value="consent.createdDate"
          :format="fullDateFormat"
          class="text-body ms-1 pt-2px" />
        <v-card-actions class="d-flex justify-end align-center pa-0">
          <v-btn
            :aria-label="$t('UserSettings.oauth.deleteConsent')"
            :disabled="loading"
            color="error"
            class="ms-2"
            outlined
            rounded
            small
            @click="$emit('delete-consent')">
            <v-icon
              size="20"
              class="me-1 ms-n1">
              fa-times-circle
            </v-icon>
            {{ $t('UserSettings.oauth.deleteConsent') }}
          </v-btn>
        </v-card-actions>
      </div>
      <div v-if="consent" class="mb-6">
        <template v-for="scope in orderedScopes">
          <div
            v-if="$te(`oAuthConsent.scope.${scope}.name`)"
            :key="scope">
            <v-checkbox
              v-model="scopeSelection[scope]"
              :value="scope"
              :aria-label="$t(`oAuthConsent.scope.${scope}.name`)"
              :label="$t(`oAuthConsent.scope.${scope}.name`)"
              :ripple="false"
              name="scope"
              class="font-weight-bold ms-n1 mt-2"
              on-icon="fa-check-square"
              off-icon="far fa-square"
              readonly />
            <div class="ms-7 mt-n3 text-subtitle">{{ $t(`oAuthConsent.scope.${scope}.description`) }}</div>
          </div>
        </template>
      </div>
      <div class="d-flex flex-nowrap align-center">
        <v-card-title class="text-header pa-0">
          {{ $t('UserSettings.oauth.oauthTokens') }}
        </v-card-title>
        <v-card-actions v-if="tokens?.length" class="d-flex justify-end align-center pa-0 ms-2">
          <v-btn
            :aria-label="$t('UserSettings.oauth.deleteAllTokens')"
            :disabled="loading"
            color="error"
            outlined
            rounded
            small
            @click="$emit('delete-tokens')">
            <v-icon
              size="20"
              class="me-1 ms-n1">
              fa-times-circle
            </v-icon>
            {{ $t('UserSettings.oauth.deleteAllTokens') }}
          </v-btn>
        </v-card-actions>
      </div>
      <v-data-iterator
        :items="tokens"
        class="mb-4"
        hide-default-header
        hide-default-footer>
        <template #default="props">
          <v-row>
            <v-col
              v-for="token in props.items"
              :key="token.id"
              cols="12"
              md="6"
              lg="4">
              <oauth-user-settings-token
                :token="token"
                :scopes="orderedScopes"
                :loading="loading"
                @delete-token="$emit('delete-token', token.id)" />
            </v-col>
          </v-row>
        </template>
      </v-data-iterator>
      <div v-if="client?.redirectUris?.length" class="d-inline-flex flex-column">
        <v-card-title class="text-header align-center pa-0 mb-2">
          {{ $t('UserSettings.oauth.redirectUris') }}
        </v-card-title>
        <v-chip
          v-for="uri in client.redirectUris"
          :key="uri"
          class="text-truncate mb-1"
          outlined>
          <v-icon class="me-2 ms-n2" size="24">fa-directions</v-icon>
          {{ uri }}
        </v-chip>
      </div>
    </v-expansion-panel-content>
  </v-expansion-panel>
</template>
<script>
export default {
  props: {
    client: {
      type: Object,
      default: null,
    },
    scopes: {
      type: Array,
      default: null,
    },
    tokens: {
      type: Array,
      default: null,
    },
    consent: {
      type: Object,
      default: null,
    },
    loading: {
      type: Boolean,
      default: false,
    },
    expanded: {
      type: Boolean,
      default: false,
    },
    index: {
      type: Number,
      default: () => 0,
    },
    length: {
      type: Number,
      default: () => 0,
    },
  },
  data: () => ({
    scopeSelection: {},
    fullDateFormat: {
      day: 'numeric',
      month: 'short',
      year: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
    }
  }),
  computed: {
    lastElement() {
      return this.index === this.length - 1;
    },
    consentScopes() {
      return this.consent?.scopes?.map?.(s => s.replace('SCOPE_', ''));
    },
    orderedScopes() {
      return this.scopes?.slice?.().sort?.((a, b) => {
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
  watch: {
    orderedScopes: {
      immediate: true,
      handler() {
        this.orderedScopes?.forEach?.(s => this.$set(this.scopeSelection, s, this.consentScopes?.includes?.(s) ? s : null));
      },
    },
  },
};
</script>
