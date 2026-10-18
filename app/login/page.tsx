"use client"

import type React from "react"

import { useState } from "react"
import Link from "next/link"
import { useRouter } from "next/navigation"
import { Eye, EyeOff, Mail, Lock } from "lucide-react"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { authAPI } from "@/lib/api"
import { useToast } from "@/hooks/use-toast"

export default function LoginPage() {
  const router = useRouter()
  const { toast } = useToast()
  const [showPassword, setShowPassword] = useState(false)
  const [isLoading, setIsLoading] = useState(false)
  const [formData, setFormData] = useState({ username: "", password: "", rememberMe: false })

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    
    if (!formData.username || !formData.password) {
      toast({ title: "Error", description: "Please enter username and password", variant: "destructive" })
      return
    }
    
    setIsLoading(true)
    try {
      await authAPI.login(formData.username, formData.password)
      toast({ title: "Success", description: "Logged in successfully!" })
      router.push("/dashboard")
    } catch (error: any) {
      const errorMsg = error.response?.data?.detail || "Invalid credentials. Please try again."
      toast({ title: "Error", description: errorMsg, variant: "destructive" })
    } finally {
      setIsLoading(false)
    }
  }

  return (
    <div className="flex min-h-screen bg-background">
      {/* Left Side - Branding */}
      <div className="hidden lg:flex lg:w-2/5 flex-col justify-between p-12 bg-gradient-to-br from-slate-900 via-slate-800 to-slate-950 relative overflow-hidden">
        {/* Background pattern */}
        <div className="absolute inset-0 opacity-5">
          <div className="absolute inset-0 bg-[linear-gradient(45deg,transparent_25%,rgba(6,182,212,.2)_25%,rgba(6,182,212,.2)_50%,transparent_50%,transparent_75%,rgba(6,182,212,.2)_75%,rgba(6,182,212,.2))] bg-[length:40px_40px]" />
        </div>

        <div className="relative z-10">
          {/* Logo */}
          <div className="flex items-center gap-3 mb-2">
            <img
              src="https://hebbkx1anhila5yf.public.blob.vercel-storage.com/download-YkSdJYuV3IWr3zYylNeDsulO5E0JpS.png"
              alt="Falcon Logo"
              className="w-10 h-10 object-contain"
            />
            <h1 className="text-2xl font-bold text-white">FalconScan</h1>
          </div>
          <p className="text-cyan-400 text-sm font-medium">Advanced Android APK Security Analysis</p>
        </div>

        {/* Features */}
        <div className="relative z-10 space-y-6">
          <div className="flex items-start gap-4">
            <div className="mt-1">
              <div className="w-8 h-8 rounded-lg bg-cyan-500/20 flex items-center justify-center">
                <span className="text-lg">🔍</span>
              </div>
            </div>
            <div>
              <h3 className="text-white font-semibold">Static & Dynamic Analysis</h3>
              <p className="text-slate-400 text-sm">Comprehensive APK scanning</p>
            </div>
          </div>

          <div className="flex items-start gap-4">
            <div className="mt-1">
              <div className="w-8 h-8 rounded-lg bg-cyan-500/20 flex items-center justify-center">
                <span className="text-lg">🤖</span>
              </div>
            </div>
            <div>
              <h3 className="text-white font-semibold">AI-Powered Detection</h3>
              <p className="text-slate-400 text-sm">Intelligent vulnerability detection</p>
            </div>
          </div>

          <div className="flex items-start gap-4">
            <div className="mt-1">
              <div className="w-8 h-8 rounded-lg bg-cyan-500/20 flex items-center justify-center">
                <span className="text-lg">📊</span>
              </div>
            </div>
            <div>
              <h3 className="text-white font-semibold">Security Reports</h3>
              <p className="text-slate-400 text-sm">Detailed threat analysis</p>
            </div>
          </div>

          <div className="flex items-start gap-4">
            <div className="mt-1">
              <div className="w-8 h-8 rounded-lg bg-cyan-500/20 flex items-center justify-center">
                <span className="text-lg">⚡</span>
              </div>
            </div>
            <div>
              <h3 className="text-white font-semibold">Real-time Detection</h3>
              <p className="text-slate-400 text-sm">Instant threat notifications</p>
            </div>
          </div>
        </div>

        {/* Footer */}
        <div className="relative z-10 text-sm text-slate-400">
          <p>© 2025 FalconScan Security. All rights reserved.</p>
        </div>
      </div>

      {/* Right Side - Login Form */}
      <div className="flex-1 flex items-center justify-center p-6">
        <div className="w-full max-w-md">
          <div className="mb-8">
            <h2 className="text-3xl font-bold text-white mb-2">Sign In</h2>
            <p className="text-slate-400">Access your FalconScan account</p>
          </div>

          <form onSubmit={handleSubmit} className="space-y-4">
            {/* Username Input */}
            <div>
              <label className="block text-sm font-medium text-slate-300 mb-2">Username</label>
              <div className="relative">
                <Mail className="absolute left-3 top-1/2 -translate-y-1/2 w-5 h-5 text-cyan-400" />
                <Input
                  type="text"
                  placeholder="username"
                  className="pl-10 bg-slate-800 border-slate-700 text-white placeholder:text-slate-500"
                  value={formData.username}
                  onChange={(e) => setFormData({ ...formData, username: e.target.value })}
                />
              </div>
            </div>

            {/* Password Input */}
            <div>
              <label className="block text-sm font-medium text-slate-300 mb-2">Password</label>
              <div className="relative">
                <Lock className="absolute left-3 top-1/2 -translate-y-1/2 w-5 h-5 text-cyan-400" />
                <Input
                  type={showPassword ? "text" : "password"}
                  placeholder="••••••••"
                  className="pl-10 pr-10 bg-slate-800 border-slate-700 text-white placeholder:text-slate-500"
                  value={formData.password}
                  onChange={(e) => setFormData({ ...formData, password: e.target.value })}
                />
                <button
                  type="button"
                  onClick={() => setShowPassword(!showPassword)}
                  className="absolute right-3 top-1/2 -translate-y-1/2 text-slate-400 hover:text-cyan-400 cursor-pointer"
                >
                  {showPassword ? <EyeOff className="w-5 h-5" /> : <Eye className="w-5 h-5" />}
                </button>
              </div>
            </div>

            {/* Remember Me & Forgot Password */}
            <div className="flex items-center justify-between">
              <label className="flex items-center gap-2 cursor-pointer">
                <input
                  type="checkbox"
                  checked={formData.rememberMe}
                  onChange={(e) => setFormData({ ...formData, rememberMe: e.target.checked })}
                  className="w-4 h-4 rounded bg-slate-800 border-slate-700 text-cyan-500 cursor-pointer"
                />
                <span className="text-sm text-slate-400">Remember me</span>
              </label>
              <Link href="/forgot-password" className="text-sm text-cyan-400 hover:text-cyan-300 transition cursor-pointer">
                Forgot password?
              </Link>
            </div>

            {/* Sign In Button */}
            <Button
              type="submit"
              disabled={isLoading}
              className="w-full mt-6 bg-gradient-to-r from-cyan-500 to-cyan-600 hover:from-cyan-600 hover:to-cyan-700 text-slate-950 font-semibold py-2 rounded-lg transition cyber-glow-hover"
            >
              {isLoading ? "Signing in..." : "Sign In"}
            </Button>
          </form>

          {/* Divider */}
          <div className="relative my-6">
            <div className="absolute inset-0 flex items-center">
              <div className="w-full border-t border-slate-700" />
            </div>
            <div className="relative flex justify-center text-sm">
              <span className="px-2 bg-background text-slate-400">or</span>
            </div>
          </div>

          {/* Sign Up Link */}
          <p className="text-center text-slate-400">
            Don't have an account?{" "}
            <Link href="/register" className="text-cyan-400 hover:text-cyan-300 font-medium transition">
              Sign up
            </Link>
          </p>
        </div>
      </div>
    </div>
  )
}
