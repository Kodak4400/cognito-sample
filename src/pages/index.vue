<template>
  <p>Hello, Vite + Vite-vue-pages + ViteSSG</p>
  <ul>
    <li><a href="page1">page1</a></li>
    <li><a href="/about">about</a></li>
    <li><a href="/about/page2">about/page2</a></li>
  </ul>
</template>

<script setup>
import { useHead } from '@vueuse/head'
useHead({
  title: 'Hello, Vite + vite-vue-pages + ViteSSG'
})
</script>
