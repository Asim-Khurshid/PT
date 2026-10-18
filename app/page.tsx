"use client"

import Link from "next/link"
import { Button } from "@/components/ui/button"
import { Card } from "@/components/ui/card"
import { Shield, Zap, Lock, BarChart3 } from "lucide-react"
import Image from "next/image"

export default function Home() {
  return (
    <div className="min-h-screen bg-gradient-to-br from-background via-background to-secondary/10">
      {/* Navigation */}
      <nav className="border-b border-border/40 backdrop-blur-sm sticky top-0 z-50">
        <div className="max-w-6xl mx-auto px-4 py-4 flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Image
              src="https://hebbkx1anhila5yf.public.blob.vercel-storage.com/download-YkSdJYuV3IWr3zYylNeDsulO5E0JpS.png"
              alt="Falcon Logo"
              width={32}
              height={32}
              className="w-8 h-8 object-contain"
            />
            <span className="text-xl font-bold text-foreground">FalconScan</span>
          </div>
          <div className="flex gap-3">
            <Link href="/login">
              <Button
                variant="outline"
                className="border-primary/50 text-foreground hover:bg-primary/10 bg-transparent cursor-pointer"
              >
                Sign In
              </Button>
            </Link>
            <Link href="/register">
              <Button className="bg-primary hover:bg-primary/90 text-primary-foreground cursor-pointer">Get Started</Button>
            </Link>
          </div>
        </div>
      </nav>

      {/* Hero Section */}
      <div className="max-w-6xl mx-auto px-4 py-20 text-center">
        <div className="space-y-6 mb-12">
          <h1 className="text-5xl md:text-6xl font-bold text-balance">
            Enterprise-Grade APK <span className="text-primary">Security Analysis</span>
          </h1>
          <p className="text-xl text-muted-foreground max-w-2xl mx-auto">
            Detect threats, vulnerabilities, and malicious behavior in Android applications with advanced AI-powered
            scanning technology
          </p>
        </div>

        <div className="flex gap-4 justify-center mb-16">
          <Link href="/register">
            <Button size="lg" className="bg-primary hover:bg-primary/90 text-primary-foreground cursor-pointer">
              Start Scanning
            </Button>
          </Link>
          <Link href="/documentation">
            <Button
              size="lg"
              variant="outline"
              className="border-primary/50 text-foreground hover:bg-primary/10 bg-transparent cursor-pointer"
            >
              View Documentation
            </Button>
          </Link>
        </div>

        {/* Feature Cards */}
        <div className="grid md:grid-cols-4 gap-4 mb-12">
          <Card className="glassmorphism cyber-glow p-6 text-left border-0">
            <Zap className="w-8 h-8 text-primary mb-3" />
            <h3 className="font-semibold text-foreground mb-2">Real-time Analysis</h3>
            <p className="text-sm text-muted-foreground">Instant threat detection and vulnerability scanning</p>
          </Card>
          <Card className="glassmorphism cyber-glow p-6 text-left border-0">
            <Shield className="w-8 h-8 text-primary mb-3" />
            <h3 className="font-semibold text-foreground mb-2">AI-Powered</h3>
            <p className="text-sm text-muted-foreground">Machine learning based behavioral analysis</p>
          </Card>
          <Card className="glassmorphism cyber-glow p-6 text-left border-0">
            <Lock className="w-8 h-8 text-primary mb-3" />
            <h3 className="font-semibold text-foreground mb-2">Secure & Private</h3>
            <p className="text-sm text-muted-foreground">Enterprise-grade encryption and data protection</p>
          </Card>
          <Card className="glassmorphism cyber-glow p-6 text-left border-0">
            <BarChart3 className="w-8 h-8 text-primary mb-3" />
            <h3 className="font-semibold text-foreground mb-2">Detailed Reports</h3>
            <p className="text-sm text-muted-foreground">Comprehensive analysis and remediation guidance</p>
          </Card>
        </div>

        {/* Stats */}
        <div className="grid md:grid-cols-3 gap-8 py-12 border-t border-border/40">
          <div>
            <p className="text-3xl font-bold text-primary mb-2">2.5M+</p>
            <p className="text-muted-foreground">Apps Scanned</p>
          </div>
          <div>
            <p className="text-3xl font-bold text-primary mb-2">99.9%</p>
            <p className="text-muted-foreground">Detection Accuracy</p>
          </div>
          <div>
            <p className="text-3xl font-bold text-primary mb-2">24/7</p>
            <p className="text-muted-foreground">Real-time Protection</p>
          </div>
        </div>
      </div>
    </div>
  )
}
