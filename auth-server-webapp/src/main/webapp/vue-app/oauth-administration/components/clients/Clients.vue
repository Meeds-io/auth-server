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
    <div class="mx-n4">
      <application-toolbar
        :right-text-filter="{
          minCharacters: 1,
          placeholder: $t('oauth.administration.client.filterByNameOrUrl'),
          tooltip: $t('oauth.administration.client.filterByNameOrUrl'),
        }"
        class="border-box-sizing"
        @filter-text-input="keyword = $event">
        <template #left>
          <v-btn
            id="applicationToolbarLeftButton"
            :aria-label="$t('oauth.administration.client.add')"
            class="btn btn-primary text-truncate"
            @click="$emit('create-client')">
            <v-icon size="18">fa-plus</v-icon>
            <span class="text-truncate text-none ms-2">
              {{ $t('oauth.administration.client.add') }}
            </span>
          </v-btn>
        </template>
      </application-toolbar>
    </div>
    <v-data-iterator
      :items="filteredClients"
      class="mb-4"
      hide-default-header
      hide-default-footer>
      <template #default="props">
        <v-row>
          <v-col
            v-for="client in props.items"
            :key="client.uuid"
            cols="12"
            lg="6">
            <oauth-administration-client
              :client="client"
              :scopes="scopes"
              class="border-color border-radius pa-5"
              @refresh="$emit('refresh-client', client.uuid)"
              @refresh-all="$emit('refresh-clients')" />
          </v-col>
        </v-row>
      </template>
    </v-data-iterator>
  </div>
</template>
<script>
export default {
  props: {
    clients: {
      type: Array,
      default: null,
    },
    scopes: {
      type: Array,
      default: null,
    },
  },
  data: () => ({
    keyword: null,
  }),
  computed: {
    filteredClients() {
      if (this.keyword?.length) {
        return this.clients.filter(c => c.name?.toLowerCase?.()?.includes?.(this.keyword.toLowerCase()) || c.url?.includes?.(this.keyword.toLowerCase()));
      } else {
        return this.clients;
      }
    },
  },
};
</script>