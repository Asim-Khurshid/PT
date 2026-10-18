import axios from "axios"

const API_BASE_URL = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000/api"

const api = axios.create({
  baseURL: API_BASE_URL,
  headers: {
    "Content-Type": "application/json",
  },
})

// Add token to requests
api.interceptors.request.use((config) => {
  const token = typeof window !== "undefined" ? localStorage.getItem("access_token") : null
  if (token) {
    config.headers.Authorization = `Bearer ${token}`
  }
  return config
})

export const authAPI = {
  login: async (username: string, password: string) => {
    const res = await api.post("/token/", { username, password })
    if (typeof window !== "undefined" && res?.data) {
      const { access, refresh, user_id } = res.data
      if (access) localStorage.setItem("access_token", access)
      if (refresh) localStorage.setItem("refresh_token", refresh)
      if (user_id) localStorage.setItem("user_id", user_id.toString())
    }
    return res
  },
  register: async (data: any) => {
    const res = await api.post("/accounts/users/register/", data)
    if (typeof window !== "undefined" && res?.data) {
      const { access, refresh, user_id } = res.data
      // Some server responses nest tokens under different keys; handle common shapes
      if (access) localStorage.setItem("access_token", access)
      else if (res.data?.access_token) localStorage.setItem("access_token", res.data.access_token)
      if (refresh) localStorage.setItem("refresh_token", refresh)
      else if (res.data?.refresh_token) localStorage.setItem("refresh_token", res.data.refresh_token)
      if (user_id) localStorage.setItem("user_id", user_id.toString())
      else if (res.data?.user_id) localStorage.setItem("user_id", res.data.user_id.toString())
    }
    return res
  },
  logout: () => {
    if (typeof window !== "undefined") {
      localStorage.removeItem("access_token")
      localStorage.removeItem("refresh_token")
      localStorage.removeItem("user_id")
      localStorage.removeItem("ongoing_scan") // Clear any ongoing scan
    }
  },
  getMe: () => api.get("/accounts/users/me/"),
  updateProfile: (data: any) => api.patch("/accounts/users/update_profile/", data),
}

export const scansAPI = {
  list: () => api.get("/scans/"),
  create: (file: File, appName: string, packageName: string, options?: { staticAnalysis?: boolean; dynamicAnalysis?: boolean; fuzzingEnabled?: boolean; aiAnalysis?: boolean }) => {
    const formData = new FormData()
    formData.append("file_path", file)
    formData.append("app_name", appName)
    formData.append("package_name", packageName)

    if (options?.staticAnalysis !== undefined) {
      formData.append("static_analysis_enabled", String(options.staticAnalysis))
    }
    if (options?.dynamicAnalysis !== undefined) {
      formData.append("dynamic_analysis_enabled", String(options.dynamicAnalysis))
    }
    if (options?.fuzzingEnabled !== undefined) {
      formData.append("fuzzing_enabled", String(options.fuzzingEnabled))
    }
    if (options?.aiAnalysis !== undefined) {
      formData.append("ai_analysis_enabled", String(options.aiAnalysis))
    }

    return api.post("/scans/upload/", formData, {
      headers: { "Content-Type": "multipart/form-data" },
    })
  },
  get: (id: string) => api.get(`/scans/${id}/`),
  getReport: (id: string) => api.get(`/scans/${id}/report/`),
  statistics: () => api.get("/scans/statistics/"),
  rescan: (id: string) => api.post(`/scans/${id}/rescan/`),
  cancelScan: (id: string) => api.post(`/scans/${id}/cancel_scan/`),
  deleteScan: (id: string) => api.post(`/scans/${id}/delete_scan/`),
  delete: (id: string) => api.delete(`/scans/${id}/`),
  downloadPDF: (id: string) => api.get(`/scans/${id}/download_pdf/`, {
    responseType: 'blob'
  }),
  cleanupFailed: () => api.post('/scans/cleanup_failed/'),
  viewFile: (id: string, filePath: string) => api.get(`/scans/${id}/view-file/`, {
    params: { path: filePath }
  }),
  // Extended analysis endpoints
  certificateInfo: (id: string) => api.get(`/scans/${id}/certificate_info/`),
  stringsExtraction: (id: string) => api.get(`/scans/${id}/strings_extraction/`),
  entropyAnalysis: (id: string) => api.get(`/scans/${id}/entropy_analysis/`),
  decompiledSources: (id: string) => api.get(`/scans/${id}/decompiled_sources/`),
  nativeLibraries: (id: string) => api.get(`/scans/${id}/native_libraries/`),
  resourceAnalysis: (id: string) => api.get(`/scans/${id}/resource_analysis/`),
  hardcodedSecrets: (id: string) => api.get(`/scans/${id}/hardcoded_secrets/`),
  codeObfuscation: (id: string) => api.get(`/scans/${id}/code_obfuscation/`),
  aiAnalysis: (id: string, force = false) =>
    api.post(`/scans/${id}/ai_analysis/${force ? '?force=true' : ''}`),
}

export default api
