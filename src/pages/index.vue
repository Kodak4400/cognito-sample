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
interface ApiResponseCookiesMessage {
  "CloudFront-Policy": string
  "CloudFront-Signature": string
  "CloudFront-Key-Pair-Id": string
}

const login = async () => {
  show.value = true
  try {
    const result = await axios.default.post<ApiResponse>(
      'https://kmdcr0evuh.execute-api.ap-northeast-1.amazonaws.com/api/sign',
      {
        Username: username.value,
        Password: password.value,
      },
      {
        headers: { 'Content-Type': 'application/json' },
      },
    )
    console.log('start')
    console.log(result.data.message)
    const message = result.data.message as Partial<ApiResponseCookiesMessage>
    console.log(message)
    console.log('end')
    // document.cookie = `idToken=${message.idToken}`
    document.cookie = `CloudFront-Policy=${message['CloudFront-Policy']}`
    document.cookie = `CloudFront-Signature=${message['CloudFront-Signature']}`
    document.cookie = `CloudFront-Key-Pair-Id=${message['CloudFront-Key-Pair-Id']}`
    // router.push('/scratch/')
    router.push('/cookie/')
  } catch (error: unknown) {
    router.push('/404')
  }
  show.value = false
}
</script>
