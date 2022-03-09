import ApiResponse from './ApiResponse'

export const httpResponseBuilder = async (statusCode: number, body: Record<any, any>): Promise<ApiResponse> => {
  return {
    isBase64Encoded: false,
    statusCode,
    body: JSON.stringify(body),
    headers: {
      'content-type': 'application/json',
    },
  }
}
export default httpResponseBuilder
