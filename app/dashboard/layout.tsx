"use client"

import { useState, useEffect } from "react"
import Link from "next/link"
import { useRouter } from "next/navigation"
import { Menu, X, Search, LogOut, Settings, User, Upload, History, FileText, Home, Book } from "lucide-react"
import type React from "react"
import { Suspense } from "react"
import { authAPI } from "@/lib/api"
import NotificationDropdown from "@/components/NotificationDropdown"

function DashboardLayoutContent({
  children,
}: {
  children: React.ReactNode
}) {
  const router = useRouter()
  const [sidebarOpen, setSidebarOpen] = useState(true)
  const [userMenuOpen, setUserMenuOpen] = useState(false)
  const [isAuthenticated, setIsAuthenticated] = useState(false)
  const [user, setUser] = useState<any>(null)

  useEffect(() => {
    const token = typeof window !== "undefined" ? localStorage.getItem("access_token") : null
    if (!token) {
      router.push("/login")
    } else {
      setIsAuthenticated(true)
      // Fetch current user data
      authAPI.getMe()
        .then(res => setUser(res.data))
        .catch(err => {
          console.error('Failed to fetch user:', err)
          if (err.response?.status === 401) {
            authAPI.logout()
            router.push("/login")
          }
        })
    }
  }, [])

  const handleLogout = () => {
    authAPI.logout()
    router.push("/login")
  }

  if (!isAuthenticated) {
    return <div className="min-h-screen bg-background flex items-center justify-center"><p className="text-slate-400">Redirecting...</p></div>
  }

  const navItems = [
    { icon: Home, label: "Dashboard", href: "/dashboard" },
    { icon: Upload, label: "Upload APK", href: "/dashboard/upload" },
    { icon: History, label: "Scan History", href: "/dashboard/history" },
    { icon: FileText, label: "Reports", href: "/dashboard/reports" },
    { icon: Book, label: "Documentation", href: "/dashboard/documentation" },
  ]

  return (
    <div className="min-h-screen bg-background">
      {/* Sidebar */}
      <div
        className={`fixed left-0 top-0 h-screen bg-card border-r border-slate-700 transition-all duration-300 z-40 ${
          sidebarOpen ? "w-64" : "w-20"
        }`}
      >
        {/* Sidebar Header */}
          <div className="h-20 flex items-center justify-between px-6 border-b border-slate-700">
            {sidebarOpen && (
              <div className="flex items-center gap-3">
                <img
                  src="https://hebbkx1anhila5yf.public.blob.vercel-storage.com/download-YkSdJYuV3IWr3zYylNeDsulO5E0JpS.png"
                  alt="Falcon Logo"
                  className="w-8 h-8 object-contain"
                />
                <span className="text-white font-bold">FalconScan</span>
              </div>
            )}
            <button
              onClick={() => setSidebarOpen(!sidebarOpen)}
              className="p-2 hover:bg-slate-700 rounded-lg transition text-cyan-400 cursor-pointer"
            >
              {sidebarOpen ? <X className="w-5 h-5" /> : <Menu className="w-5 h-5" />}
            </button>
          </div>

          {/* Navigation Items */}
          <nav className="mt-8 space-y-2 px-3">
            {navItems.map((item, idx) => (
              <Link
                key={idx}
                href={item.href}
                className="flex items-center gap-3 px-4 py-3 rounded-lg text-slate-400 hover:text-cyan-400 hover:bg-slate-800/50 transition group cursor-pointer"
              >
                <item.icon className="w-5 h-5 flex-shrink-0 group-hover:text-cyan-400" />
                {sidebarOpen && <span className="text-sm">{item.label}</span>}
              </Link>
            ))}
          </nav>

          {/* Bottom Section */}
          <div className="absolute bottom-0 left-0 right-0 p-3 border-t border-slate-700 space-y-2">
            <Link
              href="/dashboard/settings"
              className="flex items-center gap-3 px-4 py-3 rounded-lg text-slate-400 hover:text-cyan-400 hover:bg-slate-800/50 transition cursor-pointer"
            >
              <Settings className="w-5 h-5 flex-shrink-0" />
              {sidebarOpen && <span className="text-sm">Settings</span>}
            </Link>
            <button onClick={handleLogout} className="w-full flex items-center gap-3 px-4 py-3 rounded-lg text-slate-400 hover:text-red-400 hover:bg-slate-800/50 transition cursor-pointer">
              <LogOut className="w-5 h-5 flex-shrink-0" />
              {sidebarOpen && <span className="text-sm">Logout</span>}
            </button>
          </div>
        </div>

        {/* Main Content */}
        <div className={`transition-all duration-300 ${sidebarOpen ? "ml-64" : "ml-20"}`}>
          {/* Top Navbar */}
          <div className="h-20 bg-card border-b border-slate-700 flex items-center justify-between px-8">
            <div className="flex-1">
              <div className="relative max-w-md">
                <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-500" />
                <input
                  type="text"
                  placeholder="Search scans..."
                  autoComplete="off"
                  className="w-full pl-10 pr-4 py-2 bg-slate-800 border border-slate-700 rounded-lg text-slate-300 placeholder:text-slate-500 focus:outline-none focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500 cursor-text"
                />
              </div>
            </div>

            <div className="flex items-center gap-6 ml-8">
              {/* Notifications */}
              <NotificationDropdown />

              {/* User Menu */}
              <div className="relative">
                <button
                  onClick={() => setUserMenuOpen(!userMenuOpen)}
                  className="flex items-center gap-2 p-2 hover:bg-slate-800 rounded-lg transition cursor-pointer"
                >
                  <div className="w-8 h-8 bg-gradient-to-br from-cyan-400 to-cyan-600 rounded-full flex items-center justify-center">
                    <span className="text-xs font-bold text-slate-950">
                      {user ? (user.first_name?.[0] || user.username[0]).toUpperCase() + (user.last_name?.[0] || user.username[1] || '').toUpperCase() : 'U'}
                    </span>
                  </div>
                  <span className="text-sm text-slate-300">
                    {user ? (user.first_name && user.last_name ? `${user.first_name} ${user.last_name}` : user.username) : 'Loading...'}
                  </span>
                </button>

                {userMenuOpen && (
                  <div className="absolute right-0 mt-2 w-48 bg-card border border-slate-700 rounded-lg shadow-lg overflow-hidden">
                    <Link
                      href="/dashboard/profile"
                      className="flex items-center gap-2 px-4 py-2 text-slate-300 hover:bg-slate-800 transition cursor-pointer"
                    >
                      <User className="w-4 h-4" />
                      Profile
                    </Link>
                    <button onClick={handleLogout} className="w-full flex items-center gap-2 px-4 py-2 text-slate-300 hover:bg-slate-800 transition border-t border-slate-700 cursor-pointer">
                      <LogOut className="w-4 h-4" />
                      Logout
                    </button>
                  </div>
                )}
              </div>
            </div>
          </div>

        {/* Page Content */}
        <main className="p-8">{children}</main>
      </div>
    </div>
  )
}

export default function DashboardLayout({
  children,
}: {
  children: React.ReactNode
}) {
  return (
    <Suspense fallback={<div className="min-h-screen bg-background flex items-center justify-center"><p className="text-slate-400">Loading...</p></div>}>
      <DashboardLayoutContent>{children}</DashboardLayoutContent>
    </Suspense>
  )
}
