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
      <v-card
        v-if="!loading && client"
        class="application-layout-style border-box-sizing pa-5 mx-auto"
        width="600px !important"
        max-width="100% !important"
        flat>
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
        <div class="text-header mb-4 mt-2">
          {{ $t('oAuthConsent.authorize') }}
        </div>
        <div class="mb-5">
          <span v-sanitized-html="label"></span>
        </div>
        <v-form
          method="post"
          action="/auth-server/oauth2/authorize">
          <div class="d-flex flex-column">
            <div class="font-weight-bold mb-2">
              {{ $t('oAuthConsent.scope.allowList') }}
            </div>
            <template v-for="scope in scopes">
              <oauth-consent-scope
                v-if="scope !== 'offline_access'"
                v-model="scopeSelection[scope]"
                :key="scope"
                :scope="scope"
                :consented-scopes="consentedScopes" />
            </template>
            <div class="font-weight-bold mb-2 mt-4">
              {{ $t('oAuthConsent.scope.sessionLivetime') }}
            </div>
            <v-checkbox
              v-if="hasOfflineAccessScope"
              v-model="scopeSelection['offline_access']"
              :aria-label="$t('oAuthConsent.scope.sessionLivetime.label')"
              :label="$t('oAuthConsent.scope.sessionLivetime.label')"
              name="scope"
              value="offline_access"
              class="ms-n1 mt-2"
              on-icon="fa-check-square fa-lg"
              off-icon="far fa-square fa-lg" />
            <div class="text-subtitle mb-2 mt-n2 ms-7">
              {{ $t('oAuthConsent.scope.sessionLivetime.description') }}
            </div>
          </div>
          <v-card-actions class="d-flex justify-center pa-0 mt-6">
            <input
              :value="$root.clientId"
              type="hidden"
              name="client_id">
            <input
              :value="$root.state"
              type="hidden"
              name="state">
            <v-btn
              class="btn-primary btn"
              type="submit">
              {{ $t('oAuthConsent.confirm') }}
            </v-btn>
            <v-btn
              class="btn ms-4"
              @click="cancel">
              {{ $t('oAuthConsent.cancel') }}
            </v-btn>
          </v-card-actions>
        </v-form>
      </v-card>
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
    requestScopes: null,
    loading: false,
  }),
  computed: {
    scopes() {
      return this.client
        ?.scopes
        ?.slice?.()
        ?.filter?.(s => !this.requestScopes?.length || this.requestScopes.includes(s))
        ?.sort?.((a, b) => {
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
    hasOfflineAccessScope() {
      return this.scopes.includes('offline_access');
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
        1: this.companyName
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
    this.requestScopes = this.$utils?.getQueryParam?.('scope')?.split?.(' ');

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
