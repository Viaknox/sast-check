<template>
  <div>
    <!-- ruleid: sast.js.vue-dynamic-href -->
    <a :href="link">go</a>
    <!-- ruleid: sast.js.vue-dynamic-href -->
    <a v-bind:href="user.website">site</a>
    <!-- ruleid: sast.js.vue-dynamic-href -->
    <iframe :src="embedUrl"></iframe>
    <!-- ruleid: sast.js.vue-dynamic-href -->
    <a :href="'/user/' + id">profile</a>

    <!-- ok: sast.js.vue-dynamic-href -->
    <a href="/about">about</a>
    <!-- ok: sast.js.vue-dynamic-href -->
    <a :href="sanitizeUrl(link)">go</a>
    <!-- ok: sast.js.vue-dynamic-href -->
    <a :href="'https://example.com'">fixed</a>
    <!-- ok: sast.js.vue-dynamic-href -->
    <a :class="cls" :title="t">x</a>
    <!-- ok: sast.js.vue-dynamic-href -->
    <img :alt="altText" src="/logo.png" />
  </div>
</template>
