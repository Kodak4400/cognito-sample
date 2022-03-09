/// <reference types="vitest" />

import vue from '@vitejs/plugin-vue'
import { resolve } from 'path'
import AutoImport from 'unplugin-auto-import/vite'
import Components from 'unplugin-vue-components/vite'
import { defineConfig } from 'vite'
import Pages from 'vite-plugin-pages'
import Layouts from 'vite-plugin-vue-layouts'

// https://vitejs.dev/config/
export default defineConfig({
  resolve: {
    alias: {
      '@': resolve(__dirname, 'src'),
    },
  },
  plugins: [
    vue(),
    Pages({
      extendRoute: (route, parent) => {
        if (!process.env['VITE_SSG']) return route
        if (route.component.match(/\/index\.(vue|js)$/) && route.path !== '/') {
          return {
            ...route,
            path: `${route.path}/index`,
          }
        }
        return route
      },
    }),
    Layouts(),
    AutoImport({
      imports: ['vue', 'vue-router', '@vueuse/head'],
      dts: 'src/auto-imports.d.ts',
    }),
    Components(),
  ],
  test: {
    globals: true,
    environment: 'node',
    testTimeout: 30000,
  },
})
