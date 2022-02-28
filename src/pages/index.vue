<template>
  <form>
    <label>ユーザーID</label>
    <input type="text" v-model="userId" />
    <label>パスワード</label>
    <input type="text" v-model="password" />
    <button @click.prevent="login">ログイン</button>
  </form>
</template>

<script lang="ts" setup>
import { useHead } from '@vueuse/head'
import * as AmazonCognitoIdentity from 'amazon-cognito-identity-js'
import { ref } from 'vue';

useHead({
  title: 'Hello, Vite + vite-vue-pages + ViteSSG'
})

const userId = ref('')
const password = ref('')

const login = () => {
  const id = userId.value
  const pass = password.value

  const authenticationData = {
      UserId: id,
      Password: pass,
  }
  const authenticationDetails = new AmazonCognitoIdentity.AuthenticationDetails(
      authenticationData
  )

  const poolData = {
    UserPoolId: '',
    ClientId: ''
  };
  const userPool = new AmazonCognitoIdentity.CognitoUserPool(poolData)
  const userData = {
    Username: id,
    Pool: userPool,
  }
  const cognitoUser = new AmazonCognitoIdentity.CognitoUser(userData);
  cognitoUser.authenticateUser(authenticationDetails, {
      onSuccess: function(result) {
          var idToken = result.getIdToken().getJwtToken();          // IDトークン
          var accessToken = result.getAccessToken().getJwtToken();  // アクセストークン
          var refreshToken = result.getRefreshToken().getToken();   // 更新トークン

          console.log("idToken : " + idToken);
          console.log("accessToken : " + accessToken);
          console.log("refreshToken : " + refreshToken);

          document.cookie = `idToken=${idToken}`
      },
      onFailure: function(err) {
          alert(err.message || JSON.stringify(err));
      },

      newPasswordRequired: function(userAttributes, requiredAttributes) {
        delete userAttributes.email_verified;
        cognitoUser.completeNewPasswordChallenge('', userAttributes, {
          onSuccess: function(result) {
            console.log('call result: ' + result);
          },
          onFailure: function(err) {
            alert(err.message || JSON.stringify(err));
          },
        });
      },
    });
  }

return {
  password,
  login,
  // update
}
</script>
