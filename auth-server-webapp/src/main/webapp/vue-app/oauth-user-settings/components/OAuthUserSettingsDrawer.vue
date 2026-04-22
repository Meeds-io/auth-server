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
    id="OAuthSecuritySettingsDrawer"
    ref="drawer"
    v-model="drawer"
    :loading="loading"
    :allow-expand="!expanded"
    no-x-scroll
    right
    @expand-updated="expanded = $event">
    <template #title>
      {{ $t('UserSettings.oauth.drawerTitle') }}
    </template>
    <template v-if="drawer" #content>
      <div class="pa-5">
        <oauth-user-settings-clients
          :clients="clients"
          :consents="consents"
          @refresh="refresh" />
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
  },
  data: () => ({
    drawer: false,
    expanded: false,
    loading: false,
    consents: null,
  }),
  watch: {
    expanded() {
      if (!this.expanded) {
        this.$refs.drawer.toogleExpand();
      }
    },
  },
  methods: {
    open() {
      this.$refs.drawer.open();
      this.refresh();
      if (!this.expanded) {
        window.setTimeout(() => this.$refs.drawer.toogleExpand(), 50);
      }
    },
    close() {
      this.$refs.drawer.close();
    },
    async refresh() {
      this.loading = true;
      try {
        this.consents = await this.$oAuthConsentService.getConsents();
      } finally {
        this.loading = false;
      }
    },
  },
};
</script>
