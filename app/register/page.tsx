"use client"

import type React from "react"

import { useState } from "react"
import Link from "next/link"
import { useRouter } from "next/navigation"
import { Eye, EyeOff, Mail, Lock, User } from "lucide-react"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { authAPI } from "@/lib/api"
import { useToast } from "@/hooks/use-toast"

export default function RegisterPage() {
  const router = useRouter()
  const { toast } = useToast()
  const [showPassword, setShowPassword] = useState(false)
  const [showConfirmPassword, setShowConfirmPassword] = useState(false)
  const [isLoading, setIsLoading] = useState(false)
  const [passwordStrength, setPasswordStrength] = useState(0)
  const [formData, setFormData] = useState({
    username: "",
    email: "",
    firstName: "",
    lastName: "",
    password: "",
    confirmPassword: "",
    termsAccepted: false,
  })

  const calculatePasswordStrength = (pwd: string) => {
    let strength = 0
    if (pwd.length >= 8) strength++
    if (/[A-Z]/.test(pwd)) strength++
    if (/[a-z]/.test(pwd)) strength++
    if (/[0-9]/.test(pwd)) strength++
    if (/[^A-Za-z0-9]/.test(pwd)) strength++
    setPasswordStrength(strength)
  }

  const handlePasswordChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const newPassword = e.target.value
    setFormData({ ...formData, password: newPassword })
    calculatePasswordStrength(newPassword)
  }

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    
    if (!formData.email.includes('@')) {
      toast({ title: "Error", description: "Please enter a valid email address", variant: "destructive" })
      return
    }
    
    if (formData.password !== formData.confirmPassword) {
      toast({ title: "Error", description: "Passwords do not match", variant: "destructive" })
      return
    }
    
    if (!formData.termsAccepted) {
      toast({ title: "Error", description: "Please accept the terms and conditions", variant: "destructive" })
      return
    }
    
    if (!formData.username || !formData.email || !formData.password) {
      toast({ title: "Error", description: "Please fill in all required fields", variant: "destructive" })
      return
    }
    
    setIsLoading(true)
    try {
      await authAPI.register({
        username: formData.username,
        email: formData.email,
        first_name: formData.firstName,
        last_name: formData.lastName,
        password: formData.password,
        password_confirm: formData.confirmPassword,
      })
      toast({ title: "Success", description: "Account created! Please sign in." })
      router.push("/login")
    } catch (error: any) {
      const errorMsg = error.response?.data?.username?.[0] || error.response?.data?.email?.[0] || error.response?.data?.password?.[0] || "Registration failed. Please try again."
      toast({ title: "Error", description: errorMsg, variant: "destructive" })
    } finally {
      setIsLoading(false)
    }
  }

  const strengthLabels = ["Very Weak", "Weak", "Fair", "Good", "Strong"]
  const strengthColors = ["bg-red-500", "bg-orange-500", "bg-yellow-500", "bg-lime-500", "bg-green-500"]

  return (
    <div className="flex min-h-screen bg-background">
      {/* Left Side - Branding */}
      <div className="hidden lg:flex lg:w-2/5 flex-col justify-between p-12 bg-gradient-to-br from-slate-900 via-slate-800 to-slate-950 relative overflow-hidden">
        <div className="absolute inset-0 opacity-5">
          <div className="absolute inset-0 bg-[linear-gradient(45deg,transparent_25%,rgba(6,182,212,.2)_25%,rgba(6,182,212,.2)_50%,transparent_50%,transparent_75%,rgba(6,182,212,.2)_75%,rgba(6,182,212,.2))] bg-[length:40px_40px]" />
        </div>

        <div className="relative z-10">
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

        <div className="relative z-10 space-y-6">
          <div className="flex items-start gap-4">
            <div className="mt-1">
              <div className="w-8 h-8 rounded-lg bg-cyan-500/20 flex items-center justify-center">
                <span className="text-lg">🔒</span>
              </div>
            </div>
            <div>
              <h3 className="text-white font-semibold">Enterprise Security</h3>
              <p className="text-slate-400 text-sm">Military-grade encryption</p>
            </div>
          </div>

          <div className="flex items-start gap-4">
            <div className="mt-1">
              <div className="w-8 h-8 rounded-lg bg-cyan-500/20 flex items-center justify-center">
                <span className="text-lg">📱</span>
              </div>
            </div>
            <div>
              <h3 className="text-white font-semibold">APK Analysis</h3>
              <p className="text-slate-400 text-sm">Deep security scanning</p>
            </div>
          </div>

          <div className="flex items-start gap-4">
            <div className="mt-1">
              <div className="w-8 h-8 rounded-lg bg-cyan-500/20 flex items-center justify-center">
                <span className="text-lg">🛡️</span>
              </div>
            </div>
            <div>
              <h3 className="text-white font-semibold">Threat Protection</h3>
              <p className="text-slate-400 text-sm">24/7 monitoring</p>
            </div>
          </div>
        </div>

        <div className="relative z-10 text-sm text-slate-400">
          <p>© 2025 FalconScan Security. All rights reserved.</p>
        </div>
      </div>

      {/* Right Side - Register Form */}
      <div className="flex-1 flex items-center justify-center p-6">
        <div className="w-full max-w-md max-h-screen overflow-y-auto">
          <div className="mb-8">
            <h2 className="text-3xl font-bold text-white mb-2">Create Account</h2>
            <p className="text-slate-400">Join FalconScan today</p>
          </div>

          <form onSubmit={handleSubmit} className="space-y-4">
            {/* Username */}
            <div>
              <label className="block text-sm font-medium text-slate-300 mb-2">Username</label>
              <div className="relative">
                <User className="absolute left-3 top-1/2 -translate-y-1/2 w-5 h-5 text-cyan-400" />
                <Input
                  type="text"
                  placeholder="@username"
                  className="pl-10 bg-slate-800 border-slate-700 text-white placeholder:text-slate-500"
                  value={formData.username}
                  onChange={(e) => setFormData({ ...formData, username: e.target.value })}
                />
              </div>
            </div>

            {/* Email */}
            <div>
              <label className="block text-sm font-medium text-slate-300 mb-2">Email Address</label>
              <div className="relative">
                <Mail className="absolute left-3 top-1/2 -translate-y-1/2 w-5 h-5 text-cyan-400" />
                <Input
                  type="email"
                  placeholder="you@example.com"
                  className="pl-10 bg-slate-800 border-slate-700 text-white placeholder:text-slate-500"
                  value={formData.email}
                  onChange={(e) => setFormData({ ...formData, email: e.target.value })}
                />
              </div>
            </div>

            {/* First & Last Name */}
            <div className="grid grid-cols-2 gap-3">
              <div>
                <label className="block text-sm font-medium text-slate-300 mb-2">First Name</label>
                <Input
                  type="text"
                  placeholder="First"
                  className="bg-slate-800 border-slate-700 text-white placeholder:text-slate-500"
                  value={formData.firstName}
                  onChange={(e) => setFormData({ ...formData, firstName: e.target.value })}
                />
              </div>
              <div>
                <label className="block text-sm font-medium text-slate-300 mb-2">Last Name</label>
                <Input
                  type="text"
                  placeholder="Last"
                  className="bg-slate-800 border-slate-700 text-white placeholder:text-slate-500"
                  value={formData.lastName}
                  onChange={(e) => setFormData({ ...formData, lastName: e.target.value })}
                />
              </div>
            </div>

            {/* Password */}
            <div>
              <label className="block text-sm font-medium text-slate-300 mb-2">Password</label>
              <div className="relative">
                <Lock className="absolute left-3 top-1/2 -translate-y-1/2 w-5 h-5 text-cyan-400" />
                <Input
                  type={showPassword ? "text" : "password"}
                  placeholder="••••••••"
                  className="pl-10 pr-10 bg-slate-800 border-slate-700 text-white placeholder:text-slate-500"
                  value={formData.password}
                  onChange={handlePasswordChange}
                />
                <button
                  type="button"
                  onClick={() => setShowPassword(!showPassword)}
                  className="absolute right-3 top-1/2 -translate-y-1/2 text-slate-400 hover:text-cyan-400 cursor-pointer"
                >
                  {showPassword ? <EyeOff className="w-5 h-5" /> : <Eye className="w-5 h-5" />}
                </button>
              </div>

              {/* Password Strength Meter */}
              <div className="mt-2 space-y-2">
                <div className="flex gap-1">
                  {[...Array(5)].map((_, i) => (
                    <div
                      key={i}
                      className={`h-1 flex-1 rounded-full transition ${
                        i < passwordStrength ? strengthColors[passwordStrength - 1] : "bg-slate-700"
                      }`}
                    />
                  ))}
                </div>
                <p className="text-xs text-slate-400">
                  Strength: <span className="text-cyan-400">{strengthLabels[Math.max(0, passwordStrength - 1)]}</span>
                </p>
              </div>
            </div>

            {/* Confirm Password */}
            <div>
              <label className="block text-sm font-medium text-slate-300 mb-2">Confirm Password</label>
              <div className="relative">
                <Lock className="absolute left-3 top-1/2 -translate-y-1/2 w-5 h-5 text-cyan-400" />
                <Input
                  type={showConfirmPassword ? "text" : "password"}
                  placeholder="••••••••"
                  className="pl-10 pr-10 bg-slate-800 border-slate-700 text-white placeholder:text-slate-500"
                  value={formData.confirmPassword}
                  onChange={(e) => setFormData({ ...formData, confirmPassword: e.target.value })}
                />
                <button
                  type="button"
                  onClick={() => setShowConfirmPassword(!showConfirmPassword)}
                  className="absolute right-3 top-1/2 -translate-y-1/2 text-slate-400 hover:text-cyan-400 cursor-pointer"
                >
                  {showConfirmPassword ? <EyeOff className="w-5 h-5" /> : <Eye className="w-5 h-5" />}
                </button>
              </div>
            </div>

            {/* Terms & Conditions */}
            <label className="flex items-start gap-2 cursor-pointer mt-4">
              <input
                type="checkbox"
                checked={formData.termsAccepted}
                onChange={(e) => setFormData({ ...formData, termsAccepted: e.target.checked })}
                className="w-4 h-4 rounded bg-slate-800 border-slate-700 text-cyan-500 cursor-pointer mt-0.5"
              />
              <span className="text-sm text-slate-400">
                I agree to the{" "}
                <Link href="/terms" className="text-cyan-400 hover:text-cyan-300 cursor-pointer">
                  Terms of Service
                </Link>{" "}
                and{" "}
                <Link href="/privacy" className="text-cyan-400 hover:text-cyan-300 cursor-pointer">
                  Privacy Policy
                </Link>
              </span>
            </label>

            {/* Create Account Button */}
            <Button
              type="submit"
              disabled={isLoading}
              className="w-full mt-6 bg-gradient-to-r from-cyan-500 to-cyan-600 hover:from-cyan-600 hover:to-cyan-700 text-slate-950 font-semibold py-2 rounded-lg transition cyber-glow-hover cursor-pointer"
            >
              {isLoading ? "Creating account..." : "Create Account"}
            </Button>
          </form>

          {/* Sign In Link */}
          <p className="text-center text-slate-400 mt-6">
            Already have an account?{" "}
            <Link href="/login" className="text-cyan-400 hover:text-cyan-300 font-medium transition cursor-pointer">
              Sign in
            </Link>
          </p>
        </div>
      </div>
    </div>
  )
}
