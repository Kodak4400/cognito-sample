<template>
  <div>
    <label>ユーザー名</label>
    <input type="text" v-model="username" />
    <label>パスワード</label>
    <input type="text" v-model="password" />
    <button @click="login" v-if="!show">ログイン</button>
    <!-- <vue-element-loading :active="show" is-full-screen /> -->
  </div>
</template>

<script lang="ts" setup>
import { useHead } from '@vueuse/head';
import * as axios from 'axios';
import { ref } from 'vue';
import { useRouter } from 'vue-router';

// if (typeof document !== 'undefined') {
//   import('vue-element-loading')
// }

useHead({
  title: 'Cognito-Sample Login',
})

const show = ref(false)
const username = ref('')
const password = ref('')
const router = useRouter()

interface ApiResponse {
  message: string
}
interface ApiResponseMessage {
  idToken: string
  accessToken: string
  refreshToken: string
}

const login = async () => {
  show.value = true
  try {
    const result = await axios.default.post<ApiResponse>(
      'https://2ha2ddgulg.execute-api.ap-northeast-1.amazonaws.com/api/signin',
      {
        Username: username.value,
        Password: password.value,
      },
      {
        headers: { 'Content-Type': 'application/json' },
      },
    )
    const message = JSON.parse(result.data.message) as Partial<ApiResponseMessage>
    document.cookie = `idToken=${message.idToken}`
    router.push('/scratch/')
  } catch (error: unknown) {
    router.push('/404')
  }
  show.value = false
}
</script>
