<template>
  <div>
    <!-- ruleid: sast.js.vue-v-html -->
    <div v-html="userBio"></div>
    <!-- ruleid: sast.js.vue-v-html -->
    <p class="x" v-html="post.body" />
    <!-- ruleid: sast.js.vue-v-html -->
    <span v-html="'<b>' + name + '</b>'"></span>
    <!-- ruleid: sast.js.vue-v-html -->
    <section v-html='renderMarkdown(text)'></section>

    <!-- ruleid: sast.js.vue-v-html -->
    <div v-html="unsanitized"></div>
    <!-- ruleid: sast.js.vue-v-html -->
    <div v-html="purifyUser"></div>
    <!-- ruleid: sast.js.vue-v-html -->
    <div v-html="escapeHtmlUser"></div>

    <!-- ok: sast.js.vue-v-html -->
    <div v-html="'<b>fixed</b>'"></div>
    <!-- ok: sast.js.vue-v-html -->
    <div v-html="sanitize(userBio)"></div>
    <!-- ok: sast.js.vue-v-html -->
    <div v-html="DOMPurify.sanitize(post.body)"></div>
    <!-- ok: sast.js.vue-v-html -->
    <div v-html="purify(html)"></div>
    <!-- ok: sast.js.vue-v-html -->
    <div>{{ userBio }}</div>
    <!-- ok: sast.js.vue-v-html -->
    <div v-text="userBio"></div>
  </div>
</template>

<script>
export default { props: ["userBio", "post", "name", "text"] };
</script>
