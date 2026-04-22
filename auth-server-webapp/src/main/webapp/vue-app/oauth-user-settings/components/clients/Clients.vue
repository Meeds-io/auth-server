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
  <div>
    <v-data-iterator
      :items="clients"
      class="mb-4"
      hide-default-header
      hide-default-footer>
      <template #default="props">
        <v-row>
          <v-col
            v-for="client in props.items"
            :key="client.uuid"
            cols="12"
            sm="2"
            md="4">
            <oauth-user-settings-client
              :client="client"
              class="border-color border-radius pa-5"
              @edit="$refs.drawer.open(client)"
              @deleted="deleteConsentByClient(client)" />
          </v-col>
        </v-row>
      </template>
    </v-data-iterator>
    <oauth-user-settings-client-drawer
      ref="drawer"
      :clients="clients"
      :consents="consents"
      @delete="deleteConsentByClient" />
  </div>
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
  computed: {
    consentsByClient() {
      return this.clients && this.consents && Object.fromEntries(this.clients?.map?.(c => [c.uuid, this.consents?.find?.(co => co.clientId === c.id)])) || {};
    },
  },
  methods: {
    async deleteConsentByClient(client) {
      this.loading = true;
      try {
        await this.$oAuthConsentService.deleteConsentByUserAndClient(client.uuid);
        this.$root.$emit('alert-message', this.$t('UserSettings.oauth.client.tokens.deleted', {0: client.name}), 'success');
        this.$emit('refresh');
      } finally {
        this.loading = false;
      }
    },
  },
};
</script>