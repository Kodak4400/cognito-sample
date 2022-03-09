import routes from 'virtual:generated-pages'
import { ViteSSG } from 'vite-ssg'
import App from './App.vue'

export const createApp = ViteSSG(App, { routes })
