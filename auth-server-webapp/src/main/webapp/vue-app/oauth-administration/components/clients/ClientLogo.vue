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
  <v-avatar
    class="py-0 ps-0 pe-4 position-relative"
    size="90"
    tile>
    <v-img
      v-if="imageSrc"
      :src="imageSrc"
      transition="none"
      width="90"
      max-height="90"
      contain
      eager />
    <v-icon
      v-else
      size="60">
      fa-image
    </v-icon>
    <div v-show="hover" class="position-absolute t-0 r-0 mt-n4">
      <v-file-input
        v-if="!resetInput"
        ref="fileInput"
        :loading="sendingImage"
        prepend-icon="fas fa-camera z-index-two rounded-circle primary-border-color primary--text white py-1 absolute-all-center"
        accept="image/*"
        class="file-selector"
        rounded
        clearable
        @change="uploadFile" />
    </div>
  </v-avatar>
</template>
<script>
export default {
  props: {
    client: {
      type: String,
      default: () => null,
    },
    hover: {
      type: Boolean,
      default: false,
    },
    create: {
      type: Boolean,
      default: false,
    },
  },
  data: () => ({
    sendingImage: false,
    uploadInProgress: false,
    uploadProgress: 0,
    maxFileSize: 2097152,
    imageData: null,
    logoUrl: null,
    resetInput: false,
  }),
  computed: {
    imageSrc() {
      if (this.client?.uuid) {
        return this.client.logoUrl;
      } else {
        return this.logoUrl || (this.imageData && this.$utils.convertImageDataAsSrc(this.imageData));
      }
    },
  },
  watch: {
    logoUrl() {
      this.$emit('logo-updated', this.logoUrl);
    },
  },
  methods: {
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
              };
              reader.readAsDataURL(file);
              return this.updateClientLogoUrl(uploadId);
            } else {
              this.$root.$emit('alert-message', this.$t('oauth.administration.client.uploadingError'), 'error');
            }
          })
          .catch(error => this.$root.$emit('alert-message', this.$t(String(error)), 'error'))
          .finally(() => this.sendingImage = false);
      }
    },
    async updateClientLogoUrl(uploadId) {
      const objectId = this.client?.uuid || crypto.randomUUID();
      await this.$fileAttachmentService.saveAttachments({
        objectType: 'oauthClient',
        objectId: objectId,
        uploadedFiles: [{uploadId}],
      });
      const data = await this.$fileAttachmentService.getAttachments('oauthClient', objectId, 0, 1);
      if (data?.attachments?.length) {
        this.logoUrl = `${eXo.env.portal.context}/${eXo.env.portal.rest}/v1/social/attachments/oauthClient/${objectId}/${data.attachments[0].id}?lastModified=${data.attachments[0].updated}`;
        if (this.client?.uuid) {
          await this.$oAuthClientService.updateClientLogoUrl(objectId, this.logoUrl);
          this.$emit('refresh');
          this.$root.$emit('alert-message', this.$t('oauth.administration.client.logoUrl.updated'), 'success');
        }
      }
    },
  },
};
</script>