export default interface ApiResponse {
  isBase64Encoded: boolean
  statusCode: number
  body: string
  headers: {
    'content-type': string
  }
}
