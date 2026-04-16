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
  <v-app>
    <main class="application-body position-static">
      <div v-if="!loading && client" class="application-layout-style pa-5">
        <div class="d-flex flex-nowrap align-center">
          <v-avatar
            class="pa-0"
            size="90"
            tile>
            <v-img :src="companyLogo" contain />
          </v-avatar>
          <div>
            <v-card-title class="text-title pb-3">
              {{ companyName }}
            </v-card-title>
            <v-card-subtitle class="pb-0">
              <a
                :aria-label="$t('oAuthConsent.goBackHome')"
                href="/"
                target="_blank"
                class="d-flex">
                {{ $t('oAuthConsent.goBackHome') }}
                <v-icon size="12" class="text-link ms-1">fa-external-link-alt</v-icon>
              </a>
            </v-card-subtitle>
          </div>
        </div>
        <div class="text-title mb-5">
          {{ $t('oAuthConsent.authorize') }}
        </div>
        <div class="mb-5">
          <span v-sanitized-html="label"></span>
        </div>
        <v-card class="border-color border-radius pa-5" flat>
          <div class="d-flex flex-nowrap">
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
          </div>
          <v-form
            method="post"
            action="/auth-server/oauth2/authorize">
            <div class="d-flex flex-column">
              <v-card-title class="text-header ps-0 pb-0 pt-3 mb-n2">
                {{ $t('oAuthConsent.scope.allowList') }}
              </v-card-title>
              <oauth-consent-scope
                v-model="scopeSelection[scope]"
                v-for="scope in scopes"
                :key="scope"
                :scope="scope"
                :consented-scopes="consentedScopes" />
            </div>
            <v-card-actions class="pa-0 mt-4">
              <input
                :value="$root.clientId"
                type="hidden"
                name="client_id">
              <input
                :value="$root.state"
                type="hidden"
                name="state">
              <v-btn
                color="success"
                type="submit"
                outlined
                rounded
                small>
                <v-icon
                  color="success"
                  size="24"
                  class="me-2 ms-n1">
                  fa-check-circle
                </v-icon>
                {{ $t('oAuthConsent.approve') }}
              </v-btn>
              <v-btn
                class="ms-2"
                color="error"
                outlined
                rounded
                small
                @click="cancel">
                <v-icon
                  color="error"
                  size="24"
                  class="me-2 ms-n1">
                  fa-times-circle
                </v-icon>
                {{ $t('oAuthConsent.deny') }}
              </v-btn>
            </v-card-actions>
          </v-form>
        </v-card>
      </div>
    </main>
  </v-app>
</template>
<script>
export default {
  data: () => ({
    client: null,
    companyName: eXo.env.portal.companyName,
    companyLogo: eXo.env.portal.companyLogo,
    scopeSelection: {},
    consents: null,
    loading: false,
  }),
  computed: {
    scopes() {
      return this.client?.scopes?.slice?.()?.sort?.((a, b) => {
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
    clientUuid() {
      return this.client?.uuid;
    },
    consent() {
      return this.clientUuid && this.consents.find(c => c.clientId === this.$root.clientId);
    },
    consentedScopes() {
      return this.consent?.scopes?.map?.(s => s.replace('SCOPE_', ''));
    },
    label() {
      return this.$t('oAuthConsent.doYouAuthorizeApp', {
        0: `<strong>${this.client?.name}</strong>`,
        1: `<strong>${this.companyName}</strong>`
      });
    },
  },
  watch: {
    scopes: {
      immediate: true,
      handler() {
        this.scopes?.forEach?.(s => this.$set(this.scopeSelection, s, s));
      },
    },
  },
  async created() {
    await this.init();
    this.$root.$applicationLoaded();
  },
  methods: {
    async init() {
      this.loading = true;
      try {
        this.client = await this.$oAuthClientService.getClient(this.$root.clientId);
        this.consents = await this.$oAuthConsentService.getConsents();
      } finally {
        this.loading = false;
      }
    },
    cancel() {
      window.close();
    },
  },
};
</script>
