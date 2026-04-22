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
    id="OAuthClientDrawer"
    ref="drawer"
    v-model="drawer"
    :loading="loading"
    allow-expand
    no-x-scroll
    right>
    <template #title>
      {{ $t('oauth.administration.createClient.drawerTitle') }}
    </template>
    <template v-if="drawer" #content>
      <v-form
        ref="form"
        v-model="isValid"
        class="pa-5"
        @submit.prevent.stop="0">
        <div class="text-header mb-2">
          {{ $t('oauth.administration.clients.mainCharacteristics') }}
        </div>
        <div class="my-2">
          {{ $t('oauth.administration.client.name') }}
        </div>
        <v-text-field
          v-model="client.name"
          :aria-label="$t('oauth.administration.client.name')"
          :placeholder="$t('oauth.administration.client.namePlaceholder')"
          name="clientName"
          class="pt-0 mb-2 border-box-sizing"
          type="text"
          mandatory
          outlined
          dense
          solo
          flat />
        <div class="mb-2">
          {{ $t('oauth.administration.clients.logo') }}
        </div>
        <oauth-administration-client-logo-input
          v-model="uploadId"
          :logo-url="client.logoUrl"
          class="mb-4" />
        <div class="mb-2">
          {{ $t('oauth.administration.clients.clientURL') }}
        </div>
        <v-text-field
          v-model="client.url"
          :aria-label="$t('oauth.administration.client.url')"
          :placeholder="$t('oauth.administration.client.urlPlaceholder')"
          name="clientUrl"
          class="pt-0 mb-2 border-box-sizing"
          type="text"
          outlined
          dense
          solo
          flat />
        <div class="mb-2">
          {{ $t('oauth.administration.clients.redirect-uris') }}
        </div>
        <v-text-field
          v-model="uri"
          :aria-label="$t('oauth.administration.client.redirectUris.inputTitle')"
          :placeholder="$t('oauth.administration.client.redirectUris.inputPlaceholder')"
          :rules="rules"
          name="allowedRedirectUri"
          class="ma-0 pt-0 border-box-sizing"
          type="text"
          outlined
          dense
          solo
          flat
          @click:append="addRedirectUri"
          @keypress.enter="addRedirectUri">
          <template v-if="uri && validUrl" #append>
            <v-btn
              :title="$t('oauth.administration.client.redirectUris.buttonTooltip')"
              class="me-n2"
              icon
              @click="addRedirectUri">
              <v-icon
                color="success"
                size="18">
                fa-check
              </v-icon>
            </v-btn>
          </template>
        </v-text-field>
        <v-list class="pa-0" dense>
          <v-list-item
            v-for="u in client.redirectUris"
            :key="u"
            :title="u"
            class="pa-0"
            dense>
            <v-list-item-title class="pb-1">
              {{ u }}
            </v-list-item-title>
            <v-list-item-action class="my-auto ms-1 me-n1">
              <v-btn
                :title="$t('oauth.administration.client.redirectUris.delete')"
                icon
                @click="removeRedirectUri(u)">
                <v-icon
                  color="error"
                  size="18">
                  fa-minus
                </v-icon>
              </v-btn>
            </v-list-item-action>
          </v-list-item>
        </v-list>
        <div class="text-header mt-4 mb-2">
          {{ $t('oauth.administration.clients.scopes') }}
        </div>
        <div
          v-for="scope in scopes"
          :key="scope">
          <v-switch
            v-model="scopeSelection[scope]"
            :aria-label="$t(`oAuthConsent.scope.${scope}.name`)"
            :label="$t(`oAuthConsent.scope.${scope}.name`)"
            :title="$t(`oAuthConsent.scope.${scope}.description`)"
            :name="`scope-${scope}`"
            :disabled="scopeSelection[scope] && scope === 'openid'"
            class="mt-2" />
        </div>
        <div class="text-header mt-4 mb-2">
          {{ $t('oauth.administration.clients.access') }}
        </div>
        <v-switch
          v-model="client.enabled"
          :label="$t('oauth.administration.client.enabled')"
          name="scope"
          class="font-weight-bold ms-0 mt-2"
          on-icon="fa-check-square"
          off-icon="far fa-square" />
        <v-switch
          v-model="client.displayed"
          :label="$t('oauth.administration.client.displayToUsers')"
          name="scope"
          class="font-weight-bold ms-0 mt-2"
          on-icon="fa-check-square"
          off-icon="far fa-square" />
      </v-form>
    </template>
    <template #footer>
      <div class="d-flex">
        <v-spacer />
        <v-btn
          class="btn"
          @click="close">
          {{ $t('oauth.administration.cancel') }}
        </v-btn>
        <v-btn
          :disabled="!modified || disabled"
          :loading="loading"
          @click="save"
          class="btn btn-primary ms-2">
          {{ isNew ? $t('oauth.administration.create') : $t('oauth.administration.update') }}
        </v-btn>
      </div>
    </template>
  </exo-drawer>
</template>
<script>
export default {
  props: {
    scopes: {
      type: Array,
      default: null,
    },
  },
  data: () => ({
    drawer: false,
    isValid: false,
    loading: false,
    isNew: false,
    client: null,
    originalClient: null,
    uploadId: null,
    uri: null,
    scopeSelection: {},
  }),
  computed: {
    clientId() {
      return this.client?.uuid;
    },
    clientScopes() {
      return this.client?.scopes;
    },
    rules() {
      return [
        v => !!v?.length && (this.isValidUrl(v) || this.$t('oauth.administration.invalidUrl')),
        v => !!v?.length && (!this.isUriExists(v) || this.$t('oauth.administration.client.redirectUris.alreadyExists')),
      ];
    },
    mandatoryUri() {
      return !this.client?.redirectUris?.length;
    },
    validUrl() {
      return this.isValidUrl(this.uri) && !this.isUriExists(this.uri);
    },
    disabled() {
      return !this.client?.name?.trim?.()?.length || !this.client?.redirectUris?.length || !this.client?.scopes?.length;
    },
    modified() {
      return this.drawer && JSON.parse(JSON.stringify(this.client)) !== JSON.parse(JSON.stringify(this.originalClient));
    },
  },
  watch: {
    scopeSelection: {
      deep: true,
      handler() {
        if (this.drawer) {
          this.client.scopes = Object.keys(this.scopeSelection).filter(s => this.scopeSelection[s]);
        }
      },
    },
  },
  methods: {
    open(client) {
      this.isNew = !client;
      this.originalClient = client || {};
      this.client = client ? JSON.parse(JSON.stringify(client)) : {
        id: crypto.randomUUID(),
        uuid: crypto.randomUUID(),
        enabled: true,
        scopes: this.scopes.slice(),
        redirectUris: [],
        displayed: false,
      };
      this.scopeSelection = {};
      this.scopes.forEach(s => this.$set(this.scopeSelection, s, this.client.scopes?.includes?.(s)));
      this.uploadId = null;
      this.$refs.drawer.open();
    },
    close() {
      this.$refs.drawer.close();
    },
    addRedirectUri() {
      if (this.validUrl) {
        this.client.redirectUris.push(this.uri.trim());
        this.uri = null;
      }
    },
    removeRedirectUri(uri) {
      this.client.redirectUris = this.client.redirectUris.filter(u => u !== uri);
    },
    isUriExists(uri) {
      return this.client.redirectUris?.includes?.(uri?.trim?.());
    },
    isValidUrl(uri) {
      return this.$utils.isValidUrl(uri);
    },
    async save() {
      this.loading = true;
      try {
        if (this.isNew) {
          await this.createClient();
          this.$root.$emit('alert-message', this.$t('oauth.administration.client.created'), 'success');
        } else {
          await this.updateClient();
          this.$root.$emit('alert-message', this.$t('oauth.administration.client.updated'), 'success');
        }
        this.$emit('saved');
        this.close();
      } finally {
        this.loading = false;
      }
    },
    async createClient() {
      if (this.uploadId) {
        await this.updateClientLogoUrl();
      }
      this.client = await this.$oAuthClientService.createClient({
        name: this.client.name,
        url: this.client.url,
        logoUrl: this.client.logoUrl,
        redirectUris: this.client.redirectUris,
        scopes: this.client.scopes,
        enabled: this.client.enabled,
        displayed: this.client.displayed,
      });
    },
    async updateClient() {
      if (this.client.name !== this.originalClient.name) {
        await this.$oAuthClientService.updateClientName(this.client.uuid, this.client.name);
      }
      if (this.client.url !== this.originalClient.url) {
        await this.$oAuthClientService.updateClientUrl(this.client.uuid, this.client.url);
      }
      if (JSON.stringify(this.client.scopes) !== JSON.stringify(this.originalClient.scopes)) {
        await this.$oAuthClientService.updateClientScopes(this.client.uuid, this.client.scopes);
      }
      if (JSON.stringify(this.client.redirectUris) !== JSON.stringify(this.originalClient.redirectUris)) {
        await this.$oAuthClientService.updateClientRedirectUris(this.client.uuid, this.client.redirectUris);
      }
      if (this.client.enabled !== this.originalClient.enabled) {
        await this.$oAuthClientService.updateClientActivation(this.client.uuid, this.client.enabled);
      }
      if (this.client.displayed !== this.originalClient.displayed) {
        await this.$oAuthClientService.updateClientVisibility(this.client.uuid, this.client.displayed);
      }
      if (this.uploadId) {
        await this.updateClientLogoUrl();
        await this.$oAuthClientService.updateClientLogoUrl(this.client.uuid, this.client.logoUrl);
      }
    },
    async updateClientLogoUrl() {
      await this.$fileAttachmentService.saveAttachments({
        objectType: 'oauthClient',
        objectId: this.client.uuid,
        uploadedFiles: [{uploadId: this.uploadId}],
      });
      const data = await this.$fileAttachmentService.getAttachments('oauthClient', this.client.uuid, 0, 1);
      if (data?.attachments?.length) {
        this.client.logoUrl = `${window.location.origin}${eXo.env.portal.context}/${eXo.env.portal.rest}/v1/social/attachments/oauthClient/${this.client.uuid}/${data.attachments[0].id}?lastModified=${data.attachments[0].updated}`;
      }
    },
  },
};
</script>
