"use client"

import { useState, useEffect } from "react"
import { Lock, Eye, EyeOff, Save } from "lucide-react"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { authAPI, scansAPI } from "@/lib/api"
import { useToast } from "@/hooks/use-toast"

export default function ProfilePage() {
  const { toast } = useToast()
  const [activeTab, setActiveTab] = useState("personal")
  const [showCurrentPassword, setShowCurrentPassword] = useState(false)
  const [showNewPassword, setShowNewPassword] = useState(false)
  const [loading, setLoading] = useState(true)
  const [user, setUser] = useState<any>(null)
  const [stats, setStats] = useState<any>(null)
  const [formData, setFormData] = useState({
    firstName: "",
    lastName: "",
    email: "",
    phone: "",
    organization: "",
    jobTitle: "",
    currentPassword: "",
    newPassword: "",
    confirmPassword: "",
  })

  const [emailNotifications, setEmailNotifications] = useState({
    threats: true,
    reports: true,
    updates: false,
    promotions: false,
  })

  useEffect(() => {
    Promise.all([
      authAPI.getMe(),
      scansAPI.statistics()
    ])
      .then(([userRes, statsRes]) => {
        setUser(userRes.data)
        setStats(statsRes.data)
        setFormData({
          firstName: userRes.data.first_name || "",
          lastName: userRes.data.last_name || "",
          email: userRes.data.email || "",
          phone: "",
          organization: "",
          jobTitle: "",
          currentPassword: "",
          newPassword: "",
          confirmPassword: "",
        })
        setLoading(false)
      })
      .catch(err => {
        console.error('Failed to fetch profile data:', err)
        toast({ title: "Error", description: "Failed to load profile data", variant: "destructive" })
        setLoading(false)
      })
  }, [])

  const handleSaveProfile = async () => {
    try {
      await authAPI.updateProfile({
        first_name: formData.firstName,
        last_name: formData.lastName,
      })
      toast({ title: "Success", description: "Profile updated successfully" })
      // Refresh user data
      const userRes = await authAPI.getMe()
      setUser(userRes.data)
    } catch (error: any) {
      toast({ title: "Error", description: "Failed to update profile", variant: "destructive" })
    }
  }

  const statsData = [
    { label: "Total Scans", value: stats?.total_scans || 0 },
    { label: "This Month", value: stats?.total_scans || 0 },
  ]

  return (
    <div>
      <div className="mb-8">
        <h1 className="text-3xl font-bold text-white">Profile Settings</h1>
        <p className="text-slate-400 mt-2">Manage your account and preferences</p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-4 gap-6">
        {/* Left - Profile Card */}
        <div className="glassmorphism p-6 rounded-lg cyber-border h-fit">
          <div className="text-center mb-6">
            <div className="w-24 h-24 bg-gradient-to-br from-cyan-400 to-cyan-600 rounded-full flex items-center justify-center mx-auto mb-4 cyber-glow">
              <span className="text-4xl font-bold text-slate-950">
                {loading ? '...' : user ? (user.first_name?.[0] || user.username[0]).toUpperCase() + (user.last_name?.[0] || user.username[1] || '').toUpperCase() : '??'}
              </span>
            </div>
            <h2 className="text-white font-bold text-lg">
              {loading ? 'Loading...' : user ? (user.first_name && user.last_name ? `${user.first_name} ${user.last_name}` : user.username) : 'User'}
            </h2>
            <p className="text-slate-400 text-sm">{user?.email || 'user@example.com'}</p>
          </div>

          <div className="space-y-3 mb-6 border-t border-slate-700 pt-6">
            {statsData.map((stat, idx) => (
              <div key={idx} className="text-center">
                <p className="text-slate-400 text-xs">{stat.label}</p>
                <p className="text-cyan-400 text-2xl font-bold">{stat.value}</p>
              </div>
            ))}
          </div>

          <Button className="w-full bg-cyan-500/10 hover:bg-cyan-500/20 text-cyan-400 border border-cyan-500/30 cursor-pointer">
            Change Avatar
          </Button>
        </div>

        {/* Right - Content */}
        <div className="lg:col-span-3">
          {/* Tabs */}
          <div className="flex gap-2 mb-6 border-b border-slate-700">
            {[
              { id: "personal", label: "Personal Information" },
              { id: "security", label: "Security" },
              { id: "preferences", label: "Preferences" },
            ].map((tab) => (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id)}
                className={`px-4 py-3 font-medium transition border-b-2 cursor-pointer ${
                  activeTab === tab.id
                    ? "text-cyan-400 border-cyan-400"
                    : "text-slate-400 border-transparent hover:text-slate-300"
                }`}
              >
                {tab.label}
              </button>
            ))}
          </div>

          {/* Personal Information Tab */}
          {activeTab === "personal" && (
            <div className="glassmorphism p-6 rounded-lg cyber-border space-y-4">
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label className="block text-sm font-medium text-slate-300 mb-2">First Name</label>
                  <Input
                    value={formData.firstName}
                    onChange={(e) => setFormData({ ...formData, firstName: e.target.value })}
                    autoComplete="off"
                    className="bg-slate-800 border-slate-700 text-white"
                  />
                </div>
                <div>
                  <label className="block text-sm font-medium text-slate-300 mb-2">Last Name</label>
                  <Input
                    value={formData.lastName}
                    onChange={(e) => setFormData({ ...formData, lastName: e.target.value })}
                    autoComplete="off"
                    className="bg-slate-800 border-slate-700 text-white"
                  />
                </div>
              </div>

              <div>
                <label className="block text-sm font-medium text-slate-300 mb-2">Email (Verified)</label>
                <div className="flex gap-2">
                  <Input
                    value={formData.email}
                    disabled
                    className="bg-slate-800 border-slate-700 text-slate-400 flex-1"
                  />
                  <span className="px-3 py-2 bg-green-500/20 text-green-400 rounded-lg text-sm">✓</span>
                </div>
              </div>

              <div>
                <label className="block text-sm font-medium text-slate-300 mb-2">Phone</label>
                <Input
                  value={formData.phone}
                  onChange={(e) => setFormData({ ...formData, phone: e.target.value })}
                  autoComplete="off"
                  className="bg-slate-800 border-slate-700 text-white"
                />
              </div>

              <div>
                <label className="block text-sm font-medium text-slate-300 mb-2">Organization</label>
                <Input
                  value={formData.organization}
                  onChange={(e) => setFormData({ ...formData, organization: e.target.value })}
                  autoComplete="off"
                  className="bg-slate-800 border-slate-700 text-white"
                />
              </div>

              <div>
                <label className="block text-sm font-medium text-slate-300 mb-2">Job Title</label>
                <Input
                  value={formData.jobTitle}
                  onChange={(e) => setFormData({ ...formData, jobTitle: e.target.value })}
                  autoComplete="off"
                  className="bg-slate-800 border-slate-700 text-white"
                />
              </div>

              <div className="pt-4 border-t border-slate-700">
                <Button onClick={handleSaveProfile} className="bg-gradient-to-r from-cyan-500 to-cyan-600 hover:from-cyan-600 hover:to-cyan-700 text-slate-950 font-semibold cursor-pointer">
                  <Save className="w-4 h-4 mr-2" />
                  Save Changes
                </Button>
              </div>
            </div>
          )}

          {/* Security Tab */}
          {activeTab === "security" && (
            <div className="space-y-6">
              {/* Change Password */}
              <div className="glassmorphism p-6 rounded-lg cyber-border">
                <h3 className="text-white font-semibold mb-4">Change Password</h3>
                <div className="space-y-4">
                  <div>
                    <label className="block text-sm font-medium text-slate-300 mb-2">Current Password</label>
                    <div className="relative">
                      <Lock className="absolute left-3 top-1/2 -translate-y-1/2 w-5 h-5 text-slate-500" />
                      <Input
                        type={showCurrentPassword ? "text" : "password"}
                        value={formData.currentPassword}
                        onChange={(e) => setFormData({ ...formData, currentPassword: e.target.value })}
                        className="pl-10 pr-10 bg-slate-800 border-slate-700 text-white"
                      />
                      <button
                        type="button"
                        onClick={() => setShowCurrentPassword(!showCurrentPassword)}
                        className="absolute right-3 top-1/2 -translate-y-1/2 text-slate-400 hover:text-cyan-400 cursor-pointer"
                      >
                        {showCurrentPassword ? <EyeOff className="w-5 h-5" /> : <Eye className="w-5 h-5" />}
                      </button>
                    </div>
                  </div>

                  <div>
                    <label className="block text-sm font-medium text-slate-300 mb-2">New Password</label>
                    <div className="relative">
                      <Lock className="absolute left-3 top-1/2 -translate-y-1/2 w-5 h-5 text-slate-500" />
                      <Input
                        type={showNewPassword ? "text" : "password"}
                        value={formData.newPassword}
                        onChange={(e) => setFormData({ ...formData, newPassword: e.target.value })}
                        className="pl-10 pr-10 bg-slate-800 border-slate-700 text-white"
                      />
                      <button
                        type="button"
                        onClick={() => setShowNewPassword(!showNewPassword)}
                        className="absolute right-3 top-1/2 -translate-y-1/2 text-slate-400 hover:text-cyan-400 cursor-pointer"
                      >
                        {showNewPassword ? <EyeOff className="w-5 h-5" /> : <Eye className="w-5 h-5" />}
                      </button>
                    </div>
                  </div>

                  <div>
                    <label className="block text-sm font-medium text-slate-300 mb-2">Confirm Password</label>
                    <Input
                      type="password"
                      value={formData.confirmPassword}
                      onChange={(e) => setFormData({ ...formData, confirmPassword: e.target.value })}
                      className="bg-slate-800 border-slate-700 text-white"
                    />
                  </div>

                  <Button className="bg-gradient-to-r from-cyan-500 to-cyan-600 hover:from-cyan-600 hover:to-cyan-700 text-slate-950 font-semibold cursor-pointer">
                    Update Password
                  </Button>
                </div>
              </div>

              {/* Two-Factor Authentication */}
              <div className="glassmorphism p-6 rounded-lg cyber-border">
                <h3 className="text-white font-semibold mb-4">Two-Factor Authentication</h3>
                <p className="text-slate-400 text-sm mb-4">Add an extra layer of security to your account</p>
                <Button className="bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700" disabled>
                  Coming soon
                </Button>
              </div>
            </div>
          )}

          {/* Preferences Tab */}
          {activeTab === "preferences" && (
            <div className="glassmorphism p-6 rounded-lg cyber-border">
              <h3 className="text-white font-semibold mb-6">Email Notifications</h3>
              <div className="space-y-4">
                {[
                  { id: "threats", label: "Threat Alerts", desc: "Get notified about detected threats" },
                  { id: "reports", label: "Weekly Reports", desc: "Receive weekly security summaries" },
                  { id: "updates", label: "Product Updates", desc: "Learn about new features" },
                  { id: "promotions", label: "Promotions", desc: "Special offers and discounts" },
                ].map((notif) => (
                  <label
                    key={notif.id}
                    className="flex items-start gap-3 cursor-pointer p-3 hover:bg-slate-800/30 rounded-lg transition"
                  >
                    <input
                      type="checkbox"
                      checked={emailNotifications[notif.id as keyof typeof emailNotifications]}
                      onChange={(e) =>
                        setEmailNotifications({
                          ...emailNotifications,
                          [notif.id]: e.target.checked,
                        })
                      }
                      className="w-5 h-5 rounded bg-slate-800 border-slate-700 text-cyan-500 cursor-pointer mt-1"
                    />
                    <div>
                      <p className="text-white font-medium">{notif.label}</p>
                      <p className="text-slate-400 text-sm">{notif.desc}</p>
                    </div>
                  </label>
                ))}
              </div>

              <div className="mt-6 pt-6 border-t border-slate-700">
                <Button className="bg-gradient-to-r from-cyan-500 to-cyan-600 hover:from-cyan-600 hover:to-cyan-700 text-slate-950 font-semibold">
                  <Save className="w-4 h-4 mr-2" />
                  Save Preferences
                </Button>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  )
}
