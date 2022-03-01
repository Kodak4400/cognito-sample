<template>
  <div>
    <label>ユーザー名</label>
    <input type="text" v-model="username" />
    <label>パスワード</label>
    <input type="text" v-model="password" />
    <button @click="login">ログイン</button>
    <a href="">新規登録(未実装)</a>
  </div>
</template>

<script lang="ts" setup>
import { useHead } from '@vueuse/head'
import * as axios from 'axios'
import { ref } from 'vue';
import { useRouter } from 'vue-router'

useHead({
  title: 'Cognito-Sample Login'
})

const username = ref('')
const password = ref('')
const router = useRouter()

const login = async () => {
  const result = await axios.default.post('/api/login', {
    Username: username.value,
    Password: password.value
  })
  if (result.status !== 200) {
    router.push('/404')
  }
  router.push('/private')
}

</script>
