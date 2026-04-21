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
    <v-card :class="hover ? 'elevation-2' : 'elevation-0'" class="position-relative">
      <div class="d-flex flex-nowrap align-center">
        <v-avatar
          class="me-4"
          size="36"
          tile>
          <v-img
            v-if="client.logoUrl"
            :src="client.logoUrl"
            transition="none"
            width="36"
            max-height="36"
            contain
            eager />
          <v-icon
            v-else
            size="36">
            fa-key
          </v-icon>
        </v-avatar>
        <div :title="client.name" class="text-title text-start text-truncate flex-grow-1">
          {{ client.name }}
        </div>
        <div
          v-if="hover"
          class="d-flex flex-no-wrap me-n2 mt-n1">
          <v-btn
            :title="$t('oauth.administration.client.delete')"
            :disabled="client.system"
            color="error"
            class="ms-2"
            icon
            small
            @click="openDeleteConfirm">
            <v-icon size="16">fa-trash</v-icon>
          </v-btn>
          <v-btn
            :title="$t('oauth.administration.client.edit')"
            class="ms-2"
            icon
            small
            @click="$emit('edit')">
            <v-icon size="16">fa-edit</v-icon>
          </v-btn>
        </div>
      </div>
      <div class="d-flex align-center mt-8">
        <v-icon
          color="primary"
          size="20"
          class="me-2">
          fa-bolt
        </v-icon>
        {{ $t('oauth.administration.lastUse') }}
        <div class="ms-1">
          <date-format
            v-if="lastUsedDate"
            :value="lastUsedDate"
            :format="fullDateFormat"
            class="text-body" />
          <span v-else class="text-subtitle">
            {{ $t('oauth.administration.notUsedYet') }}
          </span>
        </div>
      </div>
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
  },
  data: () => ({
    loading: false,
    deleteConfirm: false,
    lastUsedDate: null,
    fullDateFormat: {
      day: 'numeric',
      month: 'short',
      year: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
    }
  }),
  async created() {
    try {
      this.lastUsedDate = await this.$oAuthClientService.getClientLastUsage(this.client.uuid);
    } catch {
      this.lastUsedDate = null;
    }
  },
  methods: {
    async openDeleteConfirm() {
      this.deleteConfirm = true;
      await this.$nextTick();
      this.$refs.confirmDialog.open();
    },
    async deleteClient() {
      this.loading = true;
      try {
        await this.$oAuthClientService.deleteClient(this.client?.uuid);
        this.$emit('deleted');
        this.$root.$emit('alert-message', this.$t('oauth.administration.client.deleteSuccess'), 'success');
      } finally {
        this.loading = false;
      }
    },
  },
};
</script>