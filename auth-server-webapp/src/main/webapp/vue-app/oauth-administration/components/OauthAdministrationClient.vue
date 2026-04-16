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
  <v-hover v-slot="{ hover }">
    <v-card :class="hover && !create ? 'elevation-2' : 'elevation-0'">
      <div class="d-flex flex-nowrap align-center">
        <oauth-administration-client-logo
          :client="client"
          :hover="hover || create"
          :create="create"
          @refresh="$emit('refresh')"
          @logo-updated="clientLogoUrl = $event" />
        <div class="flex-grow-1">
          <v-text-field
            v-model="clientName"
            :aria-label="$t('oauth.administration.client.name')"
            :placeholder="$t('oauth.administration.client.namePlaceholder')"
            :readonly="!clientNameEdit && !create"
            name="clientName"
            class="pt-0 mb-2 border-box-sizing"
            type="text"
            outlined
            dense
            solo
            flat
            @keypress.escape="clientNameEdit = false"
            @keypress.enter="editClientName">
            <template v-if="hover && !create" #append>
              <v-btn
                :title="$t('oauth.administration.client.editName')"
                :loading="loading.name"
                class="me-n2"
                icon
                @click="editClientName">
                <v-icon
                  color="primary"
                  size="18">
                  {{ clientNameEdit ? 'fa-save' : 'fa-edit' }}
                </v-icon>
              </v-btn>
            </template>
          </v-text-field>
          <v-text-field
            v-model="clientUrl"
            :aria-label="$t('oauth.administration.client.url')"
            :placeholder="$t('oauth.administration.client.urlPlaceholder')"
            :readonly="!clientUrlEdit && !create"
            name="clientUrl"
            class="pt-0 mb-2 border-box-sizing"
            type="text"
            outlined
            dense
            solo
            flat
            @keypress.enter="editClientUrl">
            <template v-if="hover && !create" #append>
              <v-btn
                :title="$t('oauth.administration.client.editUrl')"
                :loading="loading.url"
                class="me-n2"
                icon
                @click="editClientUrl">
                <v-icon
                  color="primary"
                  size="18">
                  {{ clientUrlEdit ? 'fa-save' : 'fa-edit' }}
                </v-icon>
              </v-btn>
            </template>
          </v-text-field>
          <date-format
            v-if="client?.createdDate"
            :value="client.createdDate"
            :format="fullDateFormat"
            class="text-body ms-1 pt-2px" />
        </div>
      </div>
      <v-row>
        <v-col :md="small && 12 || 6" cols="12">
          <oauth-administration-client-redirect-uris
            :client="client"
            :create="create"
            @refresh="$emit('refresh')"
            @redirect-uris-updated="clientRedirectUris = $event" />
        </v-col>
        <v-col :md="small && 12 || 6" cols="12">
          <oauth-administration-client-scopes
            :client="client"
            :scopes="scopes"
            :create="create"
            @refresh="$emit('refresh')"
            @scopes-updated="clientScopes = $event" />
        </v-col>
      </v-row>
      <v-switch
        v-model="clientEnabled"
        :label="$t('oauth.administration.client.enabled')"
        :loading="loading.enable"
        name="scope"
        class="font-weight-bold ms-0 mt-2"
        on-icon="fa-check-square"
        off-icon="far fa-square"
        @change="updateClientActivation" />
      <v-switch
        v-model="clientDisplayed"
        :label="$t('oauth.administration.client.displayToUsers')"
        :loading="loading.display"
        name="scope"
        class="font-weight-bold ms-0 mt-2"
        on-icon="fa-check-square"
        off-icon="far fa-square"
        @change="updateClientVisibility" />
      <v-card-actions v-if="!create" class="d-flex justify-end align-center pa-0 ms-2">
        <v-btn
          :aria-label="$t('oauth.administration.client.delete')"
          :loading="loading.deleteClient"
          :disabled="client.system"
          color="error"
          outlined
          small
          @click="openDeleteConfirm">
          <v-icon
            size="20"
            class="me-1 ms-n1">
            fa-times
          </v-icon>
          {{ $t('oauth.administration.client.delete') }}
        </v-btn>
      </v-card-actions>
      <confirm-dialog
        v-if="deleteConfirm"
        ref="confirmDialog"
        :title="$t('oauth.administration.deleteClient.confirmTitle')"
        :message="$t('oauth.administration.deleteClient.confirmMessage', {0: `<strong>${client.name}</strong>`})"
        :ok-label="$t('oauth.administration.ok')"
        :cancel-label="$t('oauth.administration.cancel')"
        @ok="deleteClient"
        @dialog-closed="deleteConfirm = false" />
    </v-card>
  </v-hover>
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
    small: {
      type: Boolean,
      default: false,
    },
    create: {
      type: Boolean,
      default: false,
    },
  },
  data: () => ({
    loading: {
      enable: false,
      name: false,
      url: false,
      logoUrl: false,
      display: false,
      deleteClient: false,
    },
    clientName: null,
    clientNameEdit: false,
    clientUrl: null,
    clientUrlEdit: false,
    clientLogoUrl: null,
    clientRedirectUris: null,
    clientScopes: null,
    clientEnabled: false,
    clientDisplayed: false,
    deleteConfirm: false,
    fullDateFormat: {
      day: 'numeric',
      month: 'short',
      year: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
    }
  }),
  computed: {
    clientId() {
      return this.client?.uuid;
    },
  },
  watch: {
    client: {
      immediate: true,
      deep: true,
      handler() {
        if (this.client) {
          this.clientName = this.client.name;
          this.clientUrl = this.client.url;
          this.clientLogoUrl = this.client.logoUrl;
          this.clientEnabled = this.client.enabled;
          this.clientDisplayed = this.client.displayed;
        }
      },
    },
  },
  methods: {
    async editClientName() {
      if (this.clientNameEdit) {
        this.loading.name = true;
        try {
          await this.$oAuthClientService.updateClientName(this.clientId, this.clientName || this.client.name);
          this.$emit('refresh');
          this.$root.$emit('alert-message', this.$t('oauth.administration.client.name.updated'), 'success');
        } finally {
          this.loading.name = false;
        }
        this.clientNameEdit = false;
      } else {
        this.clientNameEdit = true;
      }
    },
    async editClientUrl() {
      if (this.clientUrlEdit) {
        this.loading.url = true;
        try {
          await this.$oAuthClientService.updateClientUrl(this.clientId, this.clientUrl);
          this.$emit('refresh');
          this.$root.$emit('alert-message', this.$t('oauth.administration.client.url.updated'), 'success');
        } finally {
          this.loading.url = false;
        }
        this.clientUrlEdit = false;
      } else {
        this.clientUrlEdit = true;
      }
    },
    async updateClientActivation() {
      if (!this.clientId) {
        return;
      }
      this.loading.enable = true;
      try {
        await this.$oAuthClientService.updateClientActivation(this.clientId, this.clientEnabled);
        this.$emit('refresh');
        this.$root.$emit('alert-message', this.clientEnabled ? this.$t('oauth.administration.client.enabledSuccess') : this.$t('oauth.administration.client.disabledSuccess'), 'success');
      } finally {
        this.loading.enable = false;
      }
    },
    async updateClientVisibility() {
      if (!this.clientId) {
        return;
      }
      this.loading.display = true;
      try {
        await this.$oAuthClientService.updateClientVisibility(this.clientId, this.clientDisplayed);
        this.$emit('refresh');
        this.$root.$emit('alert-message', this.clientDisplayed ? this.$t('oauth.administration.client.displayedSuccess') : this.$t('oauth.administration.client.hiddenSuccess'), 'success');
      } finally {
        this.loading.display = false;
      }
    },
    async openDeleteConfirm() {
      this.deleteConfirm = true;
      await this.$nextTick();
      this.$refs.confirmDialog.open();
    },
    async deleteClient() {
      this.loading.deleteClient = true;
      try {
        await this.$oAuthClientService.deleteClient(this.clientId);
        this.$emit('refresh-all');
        this.$root.$emit('alert-message', this.$t('oauth.administration.client.deleteSuccess'), 'success');
      } finally {
        this.loading.deleteClient = false;
      }
    },
    async createClient() {
      const client = await this.$oAuthClientService.createClient({
        name: this.clientName,
        url: this.clientUrl,
        logoUrl: this.clientLogoUrl,
        redirectUris: this.clientRedirectUris,
        scopes: this.clientScopes,
        enabled: this.clientEnabled,
        displayed: this.clientDisplayed,
      });
      this.$emit('created', client);
    },
  },
};
</script>