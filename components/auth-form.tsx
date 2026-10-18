"use client"

import type React from "react"

import { useState } from "react"
import { Button } from "@/components/ui/button"
import { Card } from "@/components/ui/card"
import { Shield } from "lucide-react"

interface AuthFormProps {
  isLogin?: boolean
}

export function AuthForm({ isLogin = true }: AuthFormProps) {
  const [email, setEmail] = useState("")
  const [password, setPassword] = useState("")
  const [confirmPassword, setConfirmPassword] = useState("")
  const [loading, setLoading] = useState(false)

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault()
    setLoading(true)
    setTimeout(() => setLoading(false), 1000)
  }

  return (
    <Card className="glassmorphism border-0 p-8 max-w-md w-full">
      <div className="flex justify-center mb-8">
        <div className="w-12 h-12 bg-primary rounded-lg flex items-center justify-center cyber-glow">
          <Shield className="w-7 h-7 text-primary-foreground" />
        </div>
      </div>

      <h2 className="text-2xl font-bold text-center text-foreground mb-2">{isLogin ? "Sign In" : "Create Account"}</h2>
      <p className="text-center text-muted-foreground text-sm mb-6">
        {isLogin ? "Access your APK analysis dashboard" : "Join FalconScan to secure your applications"}
      </p>

      <form onSubmit={handleSubmit} className="space-y-4">
        <div>
          <label className="block text-sm font-medium text-foreground mb-2">Email</label>
          <input
            type="email"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            placeholder="you@example.com"
            className="w-full px-4 py-2 bg-secondary/20 border border-primary/20 rounded-lg text-foreground placeholder-muted-foreground focus:outline-none focus:border-primary focus:ring-1 focus:ring-primary/50 transition-colors"
            required
          />
        </div>

        <div>
          <label className="block text-sm font-medium text-foreground mb-2">Password</label>
          <input
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            placeholder="••••••••"
            className="w-full px-4 py-2 bg-secondary/20 border border-primary/20 rounded-lg text-foreground placeholder-muted-foreground focus:outline-none focus:border-primary focus:ring-1 focus:ring-primary/50 transition-colors"
            required
          />
        </div>

        {!isLogin && (
          <div>
            <label className="block text-sm font-medium text-foreground mb-2">Confirm Password</label>
            <input
              type="password"
              value={confirmPassword}
              onChange={(e) => setConfirmPassword(e.target.value)}
              placeholder="••••••••"
              className="w-full px-4 py-2 bg-secondary/20 border border-primary/20 rounded-lg text-foreground placeholder-muted-foreground focus:outline-none focus:border-primary focus:ring-1 focus:ring-primary/50 transition-colors"
              required
            />
          </div>
        )}

        <Button
          type="submit"
          disabled={loading}
          className="w-full bg-primary hover:bg-primary/90 text-primary-foreground font-medium py-2 rounded-lg transition-all"
        >
          {loading ? "Processing..." : isLogin ? "Sign In" : "Create Account"}
        </Button>
      </form>

      {isLogin && (
        <div className="mt-6 text-center text-sm">
          <span className="text-muted-foreground">Don't have an account? </span>
          <a href="/register" className="text-primary hover:text-primary/80 font-medium">
            Sign up
          </a>
        </div>
      )}

      {!isLogin && (
        <div className="mt-6 text-center text-sm">
          <span className="text-muted-foreground">Already have an account? </span>
          <a href="/login" className="text-primary hover:text-primary/80 font-medium">
            Sign in
          </a>
        </div>
      )}
    </Card>
  )
}
