<!--

 This file is part of the Meeds project (https://meeds.io/).

 Copyright (C) 2020 - 2023 Meeds Association contact@meeds.io

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
  <div class="d-flex flex-no-wrap align-center">
    <v-avatar
      class="me-4"
      size="36"
      tile>
      <v-img
        v-if="imageSrc"
        :src="imageSrc"
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
    <div class="position-relative overflow-hidden">
      <v-file-input
        v-if="!resetInput"
        id="oauthClientLogoFileInput"
        ref="fileInput"
        accept="image/*"
        class="position-absolute t-0 l-0 full-width pa-0 ma-0"
        prepend-icon=""
        hide-details
        hide-input
        @change="uploadFile" />
      <v-btn
        :loading="sending"
        class="position-relative z-index-two btn primary"
        border
        outlined
        @click="openFileUpload">
        {{ $t('oauth.administration.client.upload') }}
      </v-btn>
    </div>
  </div>
</template>
<script>
export default {
  props: {
    logoUrl: {
      type: String,
      default: () => null,
    },
  },
  data: () => ({
    sendingImage: false,
    uploadInProgress: false,
    uploadProgress: 0,
    maxFileSize: 2097152,
    uploadId: null,
    imageData: null,
    resetInput: false,
  }),
  computed: {
    imageSrc() {
      if (this.imageData) {
        return this.$utils.convertImageDataAsSrc(this.imageData);
      } else {
        return this.logoUrl;
      }
    },
  },
  watch: {
    uploadId() {
      this.$emit('input', this.uploadId);
    },
  },
  methods: {
    openFileUpload() {
      this.$refs.fileInput.$el.querySelector('input').click();
    },
    uploadFile(file) {
      this.$root.$emit('close-alert-message');
      if (file && file.size) {
        if (file.type && file.type.indexOf('image/') !== 0) {
          return;
        }
        if (file.size > this.maxFileSize) {
          this.$root.$emit('alert-message', this.$t('oauth.administration.client.tooBigFile.label'), 'error');
          return;
        }
        this.sendingImage = true;
        const self = this;
        return this.$uploadService.upload(file)
          .then(uploadId => {
            if (uploadId) {
              const reader = new FileReader();
              reader.onload = (e) => {
                self.imageData = e.target.result;
                self.$forceUpdate();
                self.uploadId = uploadId;
              };
              reader.readAsDataURL(file);
            } else {
              this.$root.$emit('alert-message', this.$t('oauth.administration.client.uploadingError'), 'error');
            }
          })
          .catch(error => this.$root.$emit('alert-message', this.$t(String(error)), 'error'))
          .finally(() => this.sendingImage = false);
      }
    },
  },
};
</script>