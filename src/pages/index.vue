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
  const hoge = axios
  const result = await axios.default.post('https://t5vaz2h0fg.execute-api.ap-northeast-1.amazonaws.com/api/login', {
    Username: username.value,
    Password: password.value
  }, {
    headers: { 'Content-Type': 'application/json' }
  })
  if (result.status !== 200) {
    router.push('/404')
  }
  alert(result.data)
  router.push('/private')
}

</script>
