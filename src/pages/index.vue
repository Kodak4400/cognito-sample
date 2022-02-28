<template>
  <form>
    <label>ユーザー名</label>
    <input type="text" v-model="username" />
    <label>パスワード</label>
    <input type="text" v-model="password" />
    <button @click.prevent="login">ログイン</button>
  </form>
</template>

<script lang="ts" setup>
import { useHead } from '@vueuse/head'
import * as axios from 'axios'
import { ref } from 'vue';

useHead({
  title: 'Cognito-Sample Login'
})

const username = ref('')
const password = ref('')

const login = async () => {
  const result = await axios.default.post('/api/login', {
    Username: username.value,
    Password: password.value
  })
  if (result.status !== 200) {
    console.error()
  }

}

return {
  password,
  username,
  login,
  // update
}
</script>
