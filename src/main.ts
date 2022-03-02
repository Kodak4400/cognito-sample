import routes from 'virtual:generated-pages'
import { ViteSSG } from 'vite-ssg'
// import VueElementLoading from 'vue-element-loading'
import App from './App.vue'

export const createApp = ViteSSG(App, { routes }, ({ app }) => {
  // if (!import.meta.env.SSR) {
  //   app.component('vue-element-loading', VueElementLoading)
  // }
})
