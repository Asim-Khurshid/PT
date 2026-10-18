"use client"

import { useState, useEffect } from "react"
import { Bell, Shield, Zap, Eye, Save, AlertCircle } from "lucide-react"
import { Button } from "@/components/ui/button"
import { authAPI } from "@/lib/api"
import { useToast } from "@/hooks/use-toast"

export default function SettingsPage() {
  const { toast } = useToast()
  const [activeTab, setActiveTab] = useState("general")
  const [loading, setLoading] = useState(true)
  const [user, setUser] = useState<any>(null)
  const [settings, setSettings] = useState({
    autoScan: true,
    realTimeProtection: true,
    quarantine: true,
    threatNotifications: true,
    weeklyReport: true,
    darkMode: true,
    soundAlerts: true,
    systemTheme: "dark",
    apiKey: "sk_test_••••••••••••••••",
    maxUploadSize: "100",
  })

  useEffect(() => {
    authAPI.getMe()
      .then(res => {
        setUser(res.data)
        setLoading(false)
      })
      .catch(err => {
        console.error('Failed to fetch user data:', err)
        setLoading(false)
      })
  }, [])

  const handleSaveSettings = () => {
    toast({ title: "Success", description: "Settings saved successfully" })
  }

  const tabs = [
    { id: "general", label: "General", icon: Zap },
    { id: "security", label: "Security", icon: Shield },
    { id: "notifications", label: "Notifications", icon: Bell },
    { id: "integration", label: "Integration", icon: Eye },
  ]

  return (
    <div>
      <div className="mb-8">
        <h1 className="text-3xl font-bold text-white">Settings</h1>
        <p className="text-slate-400 mt-2">Configure FalconScan preferences and behavior</p>
      </div>

      {/* Tabs */}
      <div className="flex gap-2 mb-6 border-b border-slate-700 overflow-x-auto">
        {tabs.map((tab) => (
          <button
            key={tab.id}
            onClick={() => setActiveTab(tab.id)}
            className={`px-4 py-3 font-medium transition border-b-2 flex items-center gap-2 whitespace-nowrap cursor-pointer ${
              activeTab === tab.id
                ? "text-cyan-400 border-cyan-400"
                : "text-slate-400 border-transparent hover:text-slate-300"
            }`}
          >
            <tab.icon className="w-4 h-4" />
            {tab.label}
          </button>
        ))}
      </div>

      {/* General Settings */}
      {activeTab === "general" && (
        <div className="space-y-6">
          {/* Scan Settings */}
          <div className="glassmorphism p-6 rounded-lg cyber-border">
            <h3 className="text-white font-semibold mb-6 flex items-center gap-2">
              <Zap className="w-5 h-5 text-cyan-400" />
              Scan Settings
            </h3>

            <div className="space-y-4">
              {[
                {
                  id: "autoScan",
                  label: "Auto Scan on Upload",
                  desc: "Automatically start analysis when APK is uploaded",
                },
                {
                  id: "realTimeProtection",
                  label: "Real-Time Protection",
                  desc: "Monitor system for threats continuously",
                },
                {
                  id: "quarantine",
                  label: "Auto Quarantine",
                  desc: "Automatically isolate suspicious files",
                },
              ].map((setting) => (
                <div
                  key={setting.id}
                  className="flex items-center justify-between p-3 bg-slate-800/30 rounded-lg border border-slate-700"
                >
                  <div>
                    <p className="text-white font-medium">{setting.label}</p>
                    <p className="text-slate-400 text-sm">{setting.desc}</p>
                  </div>
                  <button
                    onClick={() =>
                      setSettings({ ...settings, [setting.id]: !settings[setting.id as keyof typeof settings] })
                    }
                    className={`relative inline-flex h-8 w-14 items-center rounded-full transition cursor-pointer ${
                      settings[setting.id as keyof typeof settings] ? "bg-cyan-500" : "bg-slate-700"
                    }`}
                  >
                    <span
                      className={`inline-block h-6 w-6 transform rounded-full bg-white transition ${
                        settings[setting.id as keyof typeof settings] ? "translate-x-7" : "translate-x-1"
                      }`}
                    />
                  </button>
                </div>
              ))}
            </div>
          </div>

          {/* Theme Settings */}
          <div className="glassmorphism p-6 rounded-lg cyber-border">
            <h3 className="text-white font-semibold mb-6">Theme Settings</h3>

            <div className="space-y-4">
              <div>
                <label className="block text-sm font-medium text-slate-300 mb-3">Appearance</label>
                <div className="grid grid-cols-3 gap-3">
                  {["light", "dark", "auto"].map((theme) => (
                    <button
                      key={theme}
                      onClick={() => setSettings({ ...settings, systemTheme: theme })}
                      className={`p-3 rounded-lg border-2 transition text-center capitalize cursor-pointer ${
                        settings.systemTheme === theme
                          ? "border-cyan-500 bg-cyan-500/10"
                          : "border-slate-700 hover:border-slate-600"
                      }`}
                    >
                      <p className="text-slate-300 font-medium">{theme}</p>
                    </button>
                  ))}
                </div>
              </div>

              <div className="flex items-center justify-between p-3 bg-slate-800/30 rounded-lg border border-slate-700">
                <p className="text-white font-medium">Sound Alerts</p>
                <button
                  onClick={() => setSettings({ ...settings, soundAlerts: !settings.soundAlerts })}
                  className={`relative inline-flex h-8 w-14 items-center rounded-full transition cursor-pointer ${
                    settings.soundAlerts ? "bg-cyan-500" : "bg-slate-700"
                  }`}
                >
                  <span
                    className={`inline-block h-6 w-6 transform rounded-full bg-white transition ${
                      settings.soundAlerts ? "translate-x-7" : "translate-x-1"
                    }`}
                  />
                </button>
              </div>
            </div>
          </div>

          {/* File Upload Settings */}
          <div className="glassmorphism p-6 rounded-lg cyber-border">
            <h3 className="text-white font-semibold mb-4">File Upload</h3>
            <div>
              <label className="block text-sm font-medium text-slate-300 mb-2">Maximum Upload Size (MB)</label>
              <input
                type="number"
                value={settings.maxUploadSize}
                onChange={(e) => setSettings({ ...settings, maxUploadSize: e.target.value })}
                className="w-full px-4 py-2 bg-slate-800 border border-slate-700 rounded-lg text-white focus:outline-none focus:border-cyan-500"
              />
            </div>
          </div>
        </div>
      )}

      {/* Security Settings */}
      {activeTab === "security" && (
        <div className="space-y-6">
          <div className="glassmorphism p-6 rounded-lg cyber-border">
            <h3 className="text-white font-semibold mb-6 flex items-center gap-2">
              <Shield className="w-5 h-5 text-cyan-400" />
              Security Options
            </h3>

            <div className="space-y-4">
              <div className="bg-blue-500/10 border border-blue-500/30 p-4 rounded-lg flex gap-3">
                <AlertCircle className="w-5 h-5 text-blue-400 flex-shrink-0" />
                <div>
                  <p className="text-blue-400 font-medium">Two-Factor Authentication</p>
                  <p className="text-blue-300/70 text-sm mt-1">
                    Add an extra layer of security to protect your account
                  </p>
                </div>
              </div>

              <div className="flex items-center justify-between p-4 bg-slate-800/30 rounded-lg border border-slate-700">
                <div>
                  <p className="text-white font-medium">Enable 2FA</p>
                  <p className="text-slate-400 text-sm">Require authentication code on login</p>
                </div>
                <button
                  disabled
                  className="relative inline-flex h-8 w-14 items-center rounded-full bg-slate-700 opacity-50 cursor-not-allowed"
                >
                  <span className="inline-block h-6 w-6 transform rounded-full bg-white translate-x-1" />
                </button>
              </div>

              <Button className="w-full bg-cyan-500/10 hover:bg-cyan-500/20 text-cyan-400 border border-cyan-500/30">
                Configure 2FA
              </Button>
            </div>
          </div>

          <div className="glassmorphism p-6 rounded-lg cyber-border">
            <h3 className="text-white font-semibold mb-4">Session Management</h3>

            <div className="space-y-3">
              <div className="flex items-center justify-between p-3 bg-slate-800/30 rounded-lg border border-slate-700">
                <div>
                  <p className="text-white font-medium">Chrome • Windows</p>
                  <p className="text-slate-400 text-sm">Last active: 5 minutes ago</p>
                </div>
                <span className="text-green-400 text-sm font-medium">Active</span>
              </div>

              <div className="flex items-center justify-between p-3 bg-slate-800/30 rounded-lg border border-slate-700">
                <div>
                  <p className="text-white font-medium">Firefox • macOS</p>
                  <p className="text-slate-400 text-sm">Last active: 2 days ago</p>
                </div>
                <button className="text-red-400 hover:text-red-300 text-sm font-medium cursor-pointer">Logout</button>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Notification Settings */}
      {activeTab === "notifications" && (
        <div className="glassmorphism p-6 rounded-lg cyber-border">
          <h3 className="text-white font-semibold mb-6 flex items-center gap-2">
            <Bell className="w-5 h-5 text-cyan-400" />
            Notification Preferences
          </h3>

          <div className="space-y-4">
            {[
              {
                id: "threatNotifications",
                label: "Threat Alerts",
                desc: "Get notified immediately when threats are detected",
              },
              {
                id: "weeklyReport",
                label: "Weekly Reports",
                desc: "Receive comprehensive security summaries",
              },
            ].map((notif) => (
              <div
                key={notif.id}
                className="flex items-center justify-between p-4 bg-slate-800/30 rounded-lg border border-slate-700"
              >
                <div>
                  <p className="text-white font-medium">{notif.label}</p>
                  <p className="text-slate-400 text-sm">{notif.desc}</p>
                </div>
                <button
                  onClick={() => setSettings({ ...settings, [notif.id]: !settings[notif.id as keyof typeof settings] })}
                  className={`relative inline-flex h-8 w-14 items-center rounded-full transition ${
                    settings[notif.id as keyof typeof settings] ? "bg-cyan-500" : "bg-slate-700"
                  }`}
                >
                  <span
                    className={`inline-block h-6 w-6 transform rounded-full bg-white transition ${
                      settings[notif.id as keyof typeof settings] ? "translate-x-7" : "translate-x-1"
                    }`}
                  />
                </button>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Integration Settings */}
      {activeTab === "integration" && (
        <div className="space-y-6">
          <div className="glassmorphism p-6 rounded-lg cyber-border">
            <h3 className="text-white font-semibold mb-6">API Configuration</h3>

            <div className="space-y-4">
              <div>
                <label className="block text-sm font-medium text-slate-300 mb-2">API Key</label>
                <div className="flex gap-2">
                  <input
                    type="password"
                    value={settings.apiKey}
                    readOnly
                    className="flex-1 px-4 py-2 bg-slate-800 border border-slate-700 rounded-lg text-white focus:outline-none"
                  />
                  <Button className="bg-cyan-500/10 hover:bg-cyan-500/20 text-cyan-400 border border-cyan-500/30">
                    Copy
                  </Button>
                </div>
              </div>

              <Button className="w-full bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700">
                Regenerate API Key
              </Button>
            </div>
          </div>

          <div className="glassmorphism p-6 rounded-lg cyber-border">
            <h3 className="text-white font-semibold mb-4">Webhooks</h3>
            <p className="text-slate-400 text-sm mb-4">Configure webhooks for real-time scan notifications</p>
            <Button className="w-full bg-cyan-500/10 hover:bg-cyan-500/20 text-cyan-400 border border-cyan-500/30">
              Add Webhook
            </Button>
          </div>

          <div className="glassmorphism p-6 rounded-lg cyber-border">
            <h3 className="text-white font-semibold mb-4">Third-Party Integrations</h3>
            <div className="space-y-3">
              {["Slack", "Discord", "Teams"].map((service) => (
                <div
                  key={service}
                  className="flex items-center justify-between p-3 bg-slate-800/30 rounded-lg border border-slate-700"
                >
                  <p className="text-white font-medium">{service}</p>
                  <Button className="bg-cyan-500/10 hover:bg-cyan-500/20 text-cyan-400 border border-cyan-500/30 text-sm">
                    Connect
                  </Button>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* Save Button */}
      <div className="mt-8 flex gap-4">
        <Button onClick={handleSaveSettings} className="flex items-center gap-2 bg-gradient-to-r from-cyan-500 to-cyan-600 hover:from-cyan-600 hover:to-cyan-700 text-slate-950 font-semibold px-6 cursor-pointer">
          <Save className="w-4 h-4" />
          Save Changes
        </Button>
        <Button variant="outline" className="border-slate-600 text-slate-300 hover:bg-slate-800 bg-transparent">
          Cancel
        </Button>
      </div>
    </div>
  )
}
