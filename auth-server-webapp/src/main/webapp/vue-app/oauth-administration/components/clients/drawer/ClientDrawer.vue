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
    right
    @expand-updated="expanded = $event">
    <template #title>
      {{ $t('oauth.administration.createClient.drawerTitle') }}
    </template>
    <template v-if="drawer" #content>
      <div class="pa-5">
        <oauth-administration-client
          ref="client"
          :scopes="scopes"
          :small="!expanded"
          create
          @created="handleCreated" />
      </div>
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
          :loading="loading"
          @click="createClient"
          class="btn btn-primary ms-2">
          {{ $t('oauth.administration.create') }}
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
    expanded: false,
  }),
  methods: {
    open() {
      this.$refs.drawer.open();
    },
    close() {
      this.$refs.drawer.close();
    },
    async createClient() {
      this.loading = true;
      try {
        await this.$refs.client.createClient();
        this.$root.$emit('alert-message', this.$t('oauth.administration.client.created'), 'success');
      } finally {
        this.loading = false;
      }
    },
    handleCreated() {
      this.$emit('refresh-clients');
      this.close();
    },
  },
};
</script>
